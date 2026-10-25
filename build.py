# -*- coding: utf-8 -*-
"""lunatic-adb 合并管线：拉取上游规则源，全局精确去重、段内字节序排序，
合成 origin / lite 两份 Adblock 订阅文件。标准库实现，无第三方依赖。"""
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone

FETCH_TIMEOUT = 60
CATEGORIES = ["main", "meta", "privacy", "watermark", "login", "cookie", "whitelist"]
EDITIONS = (
    ("origin", "lunatic-adb.txt", "lunatic-adb"),
    ("lite", "lunatic-adb-lite.txt", "lunatic-adb-lite"),
)

FETCH_TIMEOUT = 60


def parse_upstream(text):
    """上游文件文本 -> 规则行列表：丢弃 [Adblock Plus 2.0] 头、! 注释与空行。"""
    lines = []
    for raw in text.splitlines():
        line = raw.strip().lstrip("\ufeff") if raw.startswith("\ufeff") else raw.strip()
        if not line or line.startswith("!") or line == "[Adblock Plus 2.0]":
            continue
        lines.append(line)
    return lines


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


def run(sources_path, out_dir, transport, version_text, stdout, retry_attempts=2, retry_delay=5):
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
        artifact = render_ruleset(title, version_text, CATEGORIES, collect_edition(config, edition, texts))
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


def fetch_url(url, timeout=FETCH_TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 lunatic-adb"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


if __name__ == "__main__":
    sys.exit(main())
