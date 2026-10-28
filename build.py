# -*- coding: utf-8 -*-
"""lunatic-adb 合并管线：拉取上游规则源，全局精确去重、段内字节序排序，
合成 origin / lite 两份 Adblock 订阅文件。标准库实现，无第三方依赖。"""
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
import re

FETCH_TIMEOUT = 90
RETRY_ATTEMPTS = 4
RETRY_DELAY = 5
CATEGORIES = ["main", "meta", "privacy", "watermark", "login", "cookie", "whitelist"]
EDITIONS = (
    ("origin", "lunatic-adb.txt", "lunatic-adb"),
    ("lite", "lunatic-adb-lite.txt", "lunatic-adb-lite"),
)


def parse_upstream(text):
    """上游文件文本 -> 规则行列表：丢弃 [Adblock Plus 2.0] 头、! 注释与空行。"""
    lines = []
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff") if raw.startswith("\ufeff") else raw.strip()
        if not line or line.startswith("!") or line == "[Adblock Plus 2.0]":
            continue
        lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# lite 净化（面向 Via / 轻量引擎的 ABP 子集）：
#   清洗规则来源：lingeringsound 官方转换管线 until_function.sh 的
#   lite_Adblock_Rules() 配方（github.com/lingeringsound/Ublock_filter_for_via），
#   并补齐其未覆盖的三处（$$ 裸形态 / $rewrite= / $stealth= / $app=）。
#   校验 oracle：Via Adblock 规则分析脚本 v1.19（Grok & Via 合作）判定器。
# ---------------------------------------------------------------------------

# 1) drop：匹配即整条移除（官方配方 lite_Adblock_Rules 的 grep -Ev 模式）
LITE_DROP_PATTERNS = [
    r"#(@?[%$?]+)#",
    r"#@?#\+js\(",
    r"\$@\$",
    r"(\$|,)~?(badfilter|empty|generichide|match-case|object|object-subrequest|removeparam)(,|$)",
    r"(\$|,)~?(csp|redirect-rule)(,|=|$)",
    r"(\$|,)~?(cname|genericblock|ghide|elemhide|ping|popunder)(,|$)",
    r"(\$|,)(redirect|removeparam|header|replace|urlskip|uritransform|ipaddress|method|csp|denyallow|permissions|to)=",
    r":(matches-path|-abp-contains|-abp-properties|contains|has-text|matches-css|matches-css-before|matches-css-after|xpath|nth-ancestor|upward|remove|style|watch-attr|matches-attr|matches-property|min-text-length)",
    r":others\(|:shadow\(",
    r"^/(\^|\\|\[|\(\?)",
    r"^\*$",
]
LITE_DROP_RE = re.compile("|".join(LITE_DROP_PATTERNS))

# 补充：官方配方漏网的 Via 读不了（实测发现，见 test）
LITE_DROP_EXTRA = [
    r"\$\$script",
    r"\$rewrite=",
    r"\$stealth=",
    r"\$app=",
]
LITE_DROP_RE_EXTRA = re.compile("|".join(LITE_DROP_EXTRA))

# 2) 剥壳：去掉不支持的修饰符但保留规则主体（官方配方 s/\$~?(important|popup|...)/$/g）
LITE_STRIP_MODS = ("important", "popup", "document", "all", "doc")

# 3) 归一：uBO/AG 别名 -> ABP 名（官方配方 sed 系列）
LITE_NORM_TABLE = [
    (re.compile(r"(\$|,)from="), r"\1domain="),
    (re.compile(r"(\$|,)strict3p(,|$)"), r"\1third-party\2"),
    (re.compile(r"(\$|,)(~?)3p(,|$)"), r"\1\2third-party\3"),
    (re.compile(r"(\$|,)~1p(,|$)"), r"\1third-party\2"),
    (re.compile(r"(\$|,)1p(,|$)"), r"\1~third-party\2"),
    (re.compile(r"(\$|,)(~?)xhr(,|$)"), r"\1\2xmlhttprequest\3"),
    (re.compile(r"(\$|,)(~?)css(,|$)"), r"\1\2stylesheet\3"),
    (re.compile(r"(\$|,)(~?)i?frame(,|$)"), r"\1\2subdocument\3"),
]


def _strip_lite_mods(line):
    """去掉 important/popup/document/all/doc 修饰符，保留规则主体（官方配方语义）。"""
    for mod in LITE_STRIP_MODS:
        line = re.sub(r"\$~?" + mod + r"(,|$)", r"$\1", line)
        line = re.sub(r",~?" + mod + r"(,|$)", r"\1", line)
    line = re.sub(r"\$,", "$", line)
    line = re.sub(r",,", ",", line)
    line = re.sub(r"\$$", "", line)
    return line


def _is_lite_droppable(line):
    """命中任一 drop 模式（官方配方 + 补充项）。"""
    return bool(LITE_DROP_RE.search(line) or LITE_DROP_RE_EXTRA.search(line))


def _clean_lite_line(line):
    """净化单行：drop -> 剥壳 -> 归一 -> 二次 drop。
    返回净化后的行；若最终形态仍违规或为空则返回 None。"""
    if _is_lite_droppable(line):
        return None
    line = _strip_lite_mods(line)
    for pat, repl in LITE_NORM_TABLE:
        line = pat.sub(repl, line)
    if not line:
        return None
    # 剥壳/归一可能暴露隐藏违规（如 $document,stealth= -> $stealth=），二次检查
    if _is_lite_droppable(line):
        return None
    return line


def _sanitize_lite_lines(lines):
    """drop -> 剥壳 -> 归一 -> 二次 drop -> 折叠去重，返回净化后的规则行。"""
    kept = {}
    for line in lines:
        cleaned = _clean_lite_line(line)
        if cleaned is None:
            continue
        key = cleaned.split("$", 1)[0] if cleaned.startswith("||") else cleaned
        if key not in kept:
            kept[key] = cleaned
        elif "$" not in cleaned and "$" in kept[key]:
            kept[key] = cleaned  # 优先保留无修饰符的裸规则
    return list(kept.values())


def sanitize_lite(lines, edition=None):
    """lite 净化入口。edition='lite' 返回净化后行列表；edition='origin' 原样；None 返回双版 dict。"""
    if edition is None:
        return {"lite": _sanitize_lite_lines(lines), "origin": list(lines)}
    if edition != "lite":
        return lines
    return _sanitize_lite_lines(lines)


def sanitize_lite_dict(lines_by_category, categories):
    """跨类别全局折叠：同一基础模式只保留首次出现类别的一条（先到先得）。
    输入 {类别: [行]}，输出同结构，但全局去重后的 lite 规则。"""
    seen = set()
    out = {cat: [] for cat in categories}
    for cat in categories:
        for line in lines_by_category.get(cat, []):
            cleaned = _clean_lite_line(line)
            if cleaned is None:
                continue
            key = cleaned.split("$", 1)[0] if cleaned.startswith("||") else cleaned
            if key in seen:
                continue
            seen.add(key)
            out[cat].append(cleaned)
    return out


# ---------------------------------------------------------------------------
# 产物校验（防回归）：对生成的 lite 产物做三项断言
#   1) Via 分析脚本 v1.19 判定的 unsupported == 0
#   2) 修正判重（去掉 $ 修饰符与 domain= 值后的 base 相同）== 0
#   3) lingeringsound 官方配方 drop 模式残留 == 0
# 返回 (ok, 报告字符串)。
# ---------------------------------------------------------------------------

VIA_SCRIPT_INJECT = re.compile(r"(##|@#+)\+js\(")
VIA_ADGUARD_SCRIPT = re.compile(r"#@?%#")
VIA_HTML_FILTER = re.compile(r"\$\$")
VIA_CSS_INJECT = re.compile(r"#@?\$#")
VIA_OTHER = re.compile(
    r"\$(\s*)(redirect|rewrite|csp|removeparam|badfilter|empty|generichide|match-case|object|object-subrequest|important|popup|document)"
    r"|,(\s*)(redirect=|app=|replace=|csp=|denyallow=|permissions=)"
    r"|:(matches-property|style|-abp-properties|-abp-contains|min-text-length|matches-path|contains|has-text|matches-css|matches-css-before|matches-css-after|if|if-not|xpath|nth-ancestor|upward|remove)\b|redirect-rule"
)
VIA_SCRIPT_UNSUPPORTED = re.compile(
    r"(##|@#+)\+js\(|#@?%#|\$\$|#@?\$#"
    r"|\$(\s*)(redirect|rewrite|csp|removeparam|badfilter|empty|generichide|match-case|object|object-subrequest|important|popup|document)"
    r"|,(\s*)(redirect=|app=|replace=|csp=|denyallow=|permissions=)"
    r"|:(matches-property|style|-abp-properties|-abp-contains|min-text-length|matches-path|contains|has-text|matches-css|matches-css-before|matches-css-after|if|if-not|xpath|nth-ancestor|upward|remove)\b|redirect-rule"
)


def _lite_dup_base(line):
    return line.split("$", 1)[0].rstrip(",") if line.startswith("||") else line


def verify_lite(artifact_text):
    """校验 lite 产物：0 unsupported / 0 修正重复 / 0 官方配方残留。返回 (ok, 报告)。"""
    lines = [
        ln for ln in artifact_text.split("\n")
        if ln.strip() and not ln.startswith("!") and not ln.startswith("[")
    ]
    unsupported = [ln for ln in lines if VIA_SCRIPT_UNSUPPORTED.search(ln)]

    # 修正判重：按 $ 前 base
    seen = {}
    for ln in lines:
        if ln.startswith("||"):
            seen.setdefault(_lite_dup_base(ln), []).append(ln)
    dups = {k: v for k, v in seen.items() if len(v) > 1}

    # 官方配方残留
    recipe_leftover = [ln for ln in lines if LITE_DROP_RE.search(ln) or LITE_DROP_RE_EXTRA.search(ln)]

    ok = not unsupported and not dups and not recipe_leftover
    report_lines = [
        f"unsupported(Via脚本): {len(unsupported)}",
        f"dup(base修正): {sum(len(v) - 1 for v in dups.values())}",
        f"recipe_residual(官方配方): {len(recipe_leftover)}",
    ]
    if unsupported:
        report_lines.append("  样例 unsupported:")
        report_lines += ["    " + ln[:100] for ln in unsupported[:5]]
    if dups:
        report_lines.append("  样例 dup:")
        for k, v in list(dups.items())[:3]:
            report_lines.append(f"    {k[:70]!r} x{len(v)}")
    return ok, "\n".join(report_lines)


HEADER_TEMPLATE = (
    "[Adblock Plus 2.0]\n"
    "! Title: {title}\n"
    "! Version: {version}\n"
    "! Total count: {total}\n"
    "! Description: 自用\n"
    "! Repository: https://github.com/Sakyvo/lunatic-adb\n"
    "! Expires: 12 hours\n"
)


def collect_edition(config, edition, texts):
    """按配置筛选出属于某一版的规则行：{类别: [行]}，仅含有内容的类别，类别序同配置。"""
    collected = {}
    for source in config["sources"]:
        if edition not in source["editions"] or source["url"] not in texts:
            continue
        collected.setdefault(source["category"], []).extend(parse_upstream(texts[source["url"]]))
    return collected


def render_ruleset(title, version, categories, lines_by_category):
    """分类规则行 -> 完整产物文本：全局精确去重（类别序先到先得）、段内 UTF-8 字节序排序。"""
    seen = set()
    sections = []
    total = 0
    for category in categories:
        kept = []
        for line in sorted(lines_by_category.get(category, []), key=lambda s: s.encode("utf-8")):
            if line in seen:
                continue
            seen.add(line)
            kept.append(line)
        total += len(kept)
        sections.append(
            "! >>>>>> " + category + " · " + str(len(kept)) + " <<<<<<\n"
            + "".join(line + "\n" for line in kept)
            + "! >>>>>> " + category + " 结束 <<<<<<\n"
        )
    return (
        HEADER_TEMPLATE.format(title=title, version=version, total=total)
        + "\n"
        + "\n".join(sections)
    )


def run(sources_path, out_dir, transport, version_text, stdout, retry_attempts=RETRY_ATTEMPTS, retry_delay=RETRY_DELAY):
    """端到端：拉取全部源（瞬时失败重试，耗尽后跳过并报告），写出双产物。全部源失败时不写文件并返回 1。"""
    with open(sources_path, encoding="utf-8") as f:
        config = json.load(f)
    if config.get("categories"):
        global CATEGORIES
        CATEGORIES = config["categories"]

    texts = {}
    for source in config["sources"]:
        url = source["url"]
        if url in texts:
            continue
        for attempt in range(retry_attempts + 1):
            try:
                texts[url] = transport(url)
                break
            except Exception as exc:  # noqa: BLE001 - 单源失败不阻断构建
                if attempt < retry_attempts:
                    time.sleep(retry_delay)
                else:
                    print(f"[skip: {url}] {exc}", file=stdout, flush=True)
    if not texts:
        return 1

    for edition, filename, title in EDITIONS:
        lines_by_category = collect_edition(config, edition, texts)
        if edition == "lite":
            lines_by_category = sanitize_lite_dict(lines_by_category, CATEGORIES)
        artifact = render_ruleset(title, version_text, CATEGORIES, lines_by_category)
        if edition == "lite":
            ok, report = verify_lite(artifact)
            print(f"[verify-lite] {report.replace(chr(10), chr(10)+'              ')}", file=stdout, flush=True)
            if not ok:
                print("[verify-lite] FAILED: lite 产物不满足 Via 兼容 / 去重约束！", file=stdout, flush=True)
        with open(os.path.join(out_dir, filename), "w", encoding="utf-8", newline="\n") as f:
            f.write(artifact)
    return 0


def beijing_now():
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")


def main(argv=None):
    root = os.path.dirname(os.path.abspath(__file__))
    return run(
        os.path.join(root, "sources.json"),
        root,
        fetch_url,
        beijing_now(),
        sys.stdout,
    )


def _curl_fetch(url, timeout):
    """curl fallback：urllib 对 TLS 断流/IncompleteRead 不稳时，curl 通常能完成。"""
    import subprocess
    proc = subprocess.run(
        ["curl", "-sL", "--compressed", "--max-time", str(timeout), url],
        capture_output=True,
    )
    if proc.returncode != 0:
        raise OSError(f"curl failed rc={proc.returncode}: {proc.stderr[:200]}")
    return proc.stdout.decode("utf-8", errors="replace")


def fetch_url(url, timeout=FETCH_TIMEOUT):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 lunatic-adb"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return _curl_fetch(url, timeout)


if __name__ == "__main__":
    sys.exit(main())
