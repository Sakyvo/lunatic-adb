# -*- coding: utf-8 -*-
"""build.py 的行为规格测试。所有测试离线：文本夹具注入，无网络。"""
import io
import json
import os
import re
import tempfile
import unittest

from build import (CATEGORIES, collect_edition, fetch_url, parse_upstream,
                   render_ruleset, run, sanitize_lite, sanitize_lite_dict, verify_lite)


CATEGORY_ORDER = ["main", "meta", "privacy", "watermark", "login", "cookie", "whitelist"]

BYD_URL = ("https://gist.githubusercontent.com/Sakyvo/a385daf67f65e09f7f7084baa7c9df87/raw/"
           "976e686edb2e6d6ab9f17a381f07f625ce1141db/BYD%25E5%25B9%25BF%25E5%2591%258A.txt")


class ShippedDefaultsTests(unittest.TestCase):
    """随仓库交付的默认值规格：模块类别常量与 sources.json 完整性。"""

    def test_module_categories_match_seven_section_english_spec(self):
        self.assertEqual(CATEGORIES, CATEGORY_ORDER)

    def setUp_sources(self):
        root = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(root, "sources.json"), encoding="utf-8") as f:
            return json.load(f)

    def test_sources_json_categories_are_english_seven_sections(self):
        config = self.setUp_sources()
        self.assertEqual(config["categories"], CATEGORY_ORDER)

    def test_sources_json_has_byd_and_main_tagged_lingeringsound(self):
        config = self.setUp_sources()
        by_source = {}
        for source in config["sources"]:
            by_source.setdefault(source["url"], source)
            self.assertIn(source["category"], config["categories"])
            self.assertTrue(source["editions"])
            self.assertTrue(set(source["editions"]) <= {"origin", "lite"})

        self.assertEqual(len(config["sources"]), 14)

        self.assertEqual(by_source[BYD_URL]["category"], "main")
        self.assertEqual(set(by_source[BYD_URL]["editions"]), {"origin", "lite"})

        for suffix, edition in (("adblock_auto.txt", "origin"), ("adblock_auto_lite.txt", "lite")):
            match = [s for url, s in by_source.items() if url.endswith(suffix)]
            self.assertEqual(len(match), 1, suffix)
            self.assertEqual(match[0]["category"], "main")
            self.assertEqual(match[0]["editions"], [edition])


class RenderRulesetTests(unittest.TestCase):
    """分类规则行 -> 完整产物文本：头部字段、段落结构、去重、字节序排序。"""

    def render(self, lines_by_category, title="lunatic-adb", version="2026-10-25 06:16:17", categories=None):
        return render_ruleset(title, version, categories or CATEGORY_ORDER, lines_by_category)

    def test_full_artifact_shape(self):
        text = self.render(
            {"main": ["||a.com^", "##.ad"], "whitelist": ["@@||c.com^"]},
            categories=["main", "whitelist"],
        )
        self.assertEqual(
            text,
            "[Adblock Plus 2.0]\n"
            "! Title: lunatic-adb\n"
            "! Version: 2026-10-25 06:16:17\n"
            "! Total count: 3\n"
            "! Description: 自用\n"
            "! Repository: https://github.com/Sakyvo/lunatic-adb\n"
            "! Expires: 12 hours\n"
            "\n"
            "! >>>>>> main · 2 <<<<<<\n"
            "##.ad\n"
            "||a.com^\n"
            "! >>>>>> main 结束 <<<<<<\n"
            "\n"
            "! >>>>>> whitelist · 1 <<<<<<\n"
            "@@||c.com^\n"
            "! >>>>>> whitelist 结束 <<<<<<\n",
        )

    def test_duplicate_line_kept_once_in_earlier_category(self):
        text = self.render({"main": ["||dup.com^"], "privacy": ["||dup.com^", "||p.com^"]})
        self.assertEqual(text.count("||dup.com^"), 1)
        self.assertIn("! >>>>>> privacy · 1 <<<<<<", text)
        self.assertEqual(text.count("! Total count: 2"), 1)

    def test_lines_sorted_by_utf8_byte_order(self):
        text = self.render({"main": ["z.com^", "||pipe.com^", "1digit.com^"]})
        body = text.split("! >>>>>> main · 3 <<<<<<\n", 1)[1]
        self.assertEqual(
            body.split("\n")[:3], ["1digit.com^", "z.com^", "||pipe.com^"]
        )

    def test_empty_category_still_emits_section(self):
        text = self.render({"main": []})
        self.assertIn("! >>>>>> main · 0 <<<<<<\n! >>>>>> main 结束 <<<<<<", text)
        self.assertIn("! Total count: 0", text)


class SanitizeLiteTests(unittest.TestCase):
    """lite 净化：以 lingeringsound 官方转换管线为权威清单，Via 分析脚本为校验 oracle。
    sanitize_lite(lines, editions) -> {edition: [lines]}。

    构造三类样例：应 drop、应剥壳、应保留，分别断言。
    """

    def setUp(self):
        # 应用全部净化步骤后的行集
        self.lines = [
            # —— 应 drop（官方配方 / Via 脚本 / 补充项）——
            "##+js(aopw, window.open)",                    # 脚本注入
            "example.com#%#//scriptlet('set-constant')",    # AdGuard 脚本
            "example.com#$#body { background: none; }",     # CSS 注入
            "example.com#?#.ad-overlay",                    # 程序化
            "example.com$$script[src*='ads']",              # HTML 过滤
            "||ads.com^$badfilter",                         # badfilter
            "||ads.com^$generichide",                       # generichide
            "||x.com^$redirect=abp-resource:blank-js",      # redirect=
            "||x.com^$rewrite=abp-resource:blank-mp4",      # rewrite=（补充）
            "||x.com^$stealth=useragent",                   # stealth=（补充）
            "||x.com^$app=com.foo",                         # app=（补充）
            "##.ad:has-text(广告)",                          # 特殊伪类
            "##.banner:matches-css-before(content: 'spon')", # matches-css-before
            "/^https?:\\/\\/ads\\./",                       # 正则
            # —— 应剥壳保留 ——
            "||pop.com^$popup",                              # $popup 剥壳
            "||doc.com^$important,image",                    # $important 剥壳
            "||x.com^$document",                             # $document 剥壳
            # —— 应原样保留 ——
            "||a.com^$third-party",                          # 基础类型
            "##.plain-ad",                                   # 常规 CSS
            "example.com##div#banner",                       # 域名限定 CSS
            "@@||c.com^",                                    # 白名单
        ]

    def test_drop_rules_are_removed(self):
        kept = sanitize_lite(self.lines, "lite")
        text = "\n".join(kept)
        for bad in (
            "##+js(", "#%#", "#$#", "#?#", "$$script[",
            "$badfilter", "$generichide", "$redirect=", "$rewrite=",
            "$stealth=", "$app=", ":has-text(", ":matches-css-before",
            r"/^https?:\/\/ads\./", "$popup", "$important", "$document",
        ):
            self.assertNotIn(bad, text, bad)

    def test_shell_and_normal_kept(self):
        kept = sanitize_lite(self.lines, "lite")
        text = "\n".join(kept)
        self.assertIn("||a.com^$third-party", text)
        self.assertIn("##.plain-ad", text)
        self.assertIn("example.com##div#banner", text)
        self.assertIn("@@||c.com^", text)

    def test_dedup_within_lite(self):
        lines = ["||dup.com^$domain=a.com", "||dup.com^$domain=b.com", "||dup.com^"]
        kept = sanitize_lite(lines, "lite")
        self.assertEqual(kept, ["||dup.com^"])

    def test_dedup_across_categories_global(self):
        """跨类别折叠：同一基础模式只保留首次出现类别的一条。"""
        lines_by_cat = {
            "main": ["||dup.com^$domain=a.com"],
            "privacy": ["||dup.com^$domain=b.com"],
        }
        out = sanitize_lite_dict(lines_by_cat, ["main", "privacy"])
        self.assertEqual(out["main"], ["||dup.com^$domain=a.com"])
        self.assertEqual(out["privacy"], [])

    def test_dedup_ignores_domain_value_variants(self):
        """同一 base 不同 domain= 值视为重复（只保留第一条）。"""
        lines_by_cat = {
            "main": ["||dup.com^$third-party,domain=a.com", "||dup.com^$domain=b.com"],
        }
        out = sanitize_lite_dict(lines_by_cat, ["main"])
        self.assertEqual(len(out["main"]), 1)
        self.assertEqual(out["main"][0], "||dup.com^$third-party,domain=a.com")

    def test_shell_exposes_hidden_unsupported_is_dropped(self):
        """剥壳可能暴露隐藏违规（$document,stealth= -> $stealth=）：二次 drop 检查必须拦截。"""
        lines = ["@@||linksflys.com^$document,stealth=referrer"]
        kept = sanitize_lite(lines, "lite")
        self.assertEqual(kept, [])
        self.assertNotIn("linksflys", "".join(kept))

    def test_verify_lite_clean_passes(self):
        """干净产物通过校验；含不支持/重复/残留则失败。"""
        clean = "[Adblock Plus 2.0]\n! Title: x\n\n##.ad\n||a.com^$third-party\n@@||c.com^\n"
        ok, report = verify_lite(clean)
        self.assertTrue(ok, report)

        bad = clean + "##+js(aopr)\n||dup.com^$domain=a.com\n||dup.com^$image\n"
        ok, report = verify_lite(bad)
        self.assertFalse(ok)
        self.assertIn("unsupported(Via脚本): 1", report)
        self.assertIn("dup(base修正): 1", report)

    def test_lite_sanitize_returns_all_editions_when_no_edition_filter(self):
        result = sanitize_lite(self.lines, None)
        self.assertEqual(sorted(result.keys()), ["lite", "origin"])
        # origin 不净化：全量保留
        self.assertEqual(result["origin"], self.lines)


class CollectEditionTests(unittest.TestCase):
    """配置 + 已拉取文本 -> 某一版的分类行字典（通用源两版共享，特供源按版归属同类别）。"""

    CONFIG = {
        "categories": CATEGORY_ORDER,
        "sources": [
            {"url": "u1", "category": "main", "editions": ["origin", "lite"]},
            {"url": "u2", "category": "main", "editions": ["origin"]},
        ],
    }

    def test_generic_source_reaches_both_editions(self):
        texts = {"u1": "||g.com^"}
        for edition in ("origin", "lite"):
            self.assertEqual(collect_edition(self.CONFIG, edition, texts), {"main": ["||g.com^"]})

    def test_exclusive_source_only_in_its_edition(self):
        texts = {"u1": "||g.com^", "u2": "||o.com^"}
        self.assertEqual(
            collect_edition(self.CONFIG, "origin", texts),
            {"main": ["||g.com^", "||o.com^"]},
        )
        self.assertEqual(collect_edition(self.CONFIG, "lite", texts), {"main": ["||g.com^"]})


class RunEndToEndTests(unittest.TestCase):
    """端到端：配置 + 注入 transport -> 双产物落盘；失败源跳过并报告；lite 净化钩子。"""

    CONFIG = {
        "categories": CATEGORY_ORDER,
        "sources": [
            {"url": "u-generic", "category": "main", "editions": ["origin", "lite"]},
            {"url": "u-origin-only", "category": "main", "editions": ["origin"]},
        ],
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sources_path = os.path.join(self.tmp.name, "sources.json")
        with open(self.sources_path, "w", encoding="utf-8") as f:
            json.dump(self.CONFIG, f, ensure_ascii=False)

    def run_build(self, transport):
        out = io.StringIO()
        code = run(self.sources_path, self.tmp.name, transport, "2026-10-25 06:16:17", out,
                   retry_attempts=1, retry_delay=0)
        return code, out.getvalue()

    def artifact(self, name):
        with open(os.path.join(self.tmp.name, name), encoding="utf-8") as f:
            return f.read()

    def test_both_artifacts_written_with_edition_scoped_sources(self):
        texts = {"u-generic": "||g.com^\n! noise\n", "u-origin-only": "||o.com^"}
        code, _ = self.run_build(lambda url: texts[url])
        self.assertEqual(code, 0)
        origin, lite = self.artifact("lunatic-adb.txt"), self.artifact("lunatic-adb-lite.txt")
        self.assertIn("! Title: lunatic-adb\n", origin)
        self.assertIn("||o.com^\n", origin)
        self.assertIn("! >>>>>> main · 2 <<<<<<", origin)
        self.assertIn("! Title: lunatic-adb-lite\n", lite)
        self.assertNotIn("||o.com^", lite)
        self.assertIn("||g.com^", lite)

    def test_artifacts_use_lf_line_endings(self):
        self.run_build(lambda url: {"u-generic": "||g.com^", "u-origin-only": ""}[url])
        self.assertNotIn("\r", self.artifact("lunatic-adb.txt"))

    def test_failed_source_is_skipped_with_report(self):
        def transport(url):
            if url == "u-origin-only":
                raise OSError("connection refused")
            return "||g.com^"

        code, report = self.run_build(transport)
        self.assertEqual(code, 0)
        self.assertIn("[skip: u-origin-only]", report)
        self.assertIn("||g.com^", self.artifact("lunatic-adb.txt"))
        self.assertIn("! >>>>>> main · 1 <<<<<<", self.artifact("lunatic-adb.txt"))

    def test_all_sources_failed_aborts_without_writing(self):
        code, _ = self.run_build(self.fail_all)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "lunatic-adb.txt")))

    def fail_all(self, url):
        raise OSError("down")

    def run_build_with_retries(self, transport, attempts, delay):
        out = io.StringIO()
        code = run(self.sources_path, self.tmp.name, transport, "2026-10-25 06:16:17", out,
                   retry_attempts=attempts, retry_delay=delay)
        return code, out.getvalue()

    def test_transient_failure_is_retried_before_skip(self):
        calls = {"u-generic": 0}

        def flaky(url):
            if url == "u-generic":
                calls["u-generic"] += 1
                if calls["u-generic"] == 1:
                    raise OSError("transient tls eof")
            return {"u-generic": "||g.com^", "u-origin-only": "||o.com^"}[url]

        code, report = self.run_build_with_retries(flaky, attempts=2, delay=0)
        self.assertEqual(code, 0)
        self.assertEqual(calls["u-generic"], 2)
        self.assertNotIn("[skip:", report)
        self.assertIn("||g.com^", self.artifact("lunatic-adb.txt"))

    def test_retries_exhausted_falls_back_to_skip(self):
        calls = {"u-generic": 0}

        def always_down(url):
            calls[url] = calls.get(url, 0) + 1
            raise OSError("down")

        code, report = self.run_build_with_retries(always_down, attempts=2, delay=0)
        self.assertEqual(code, 1)
        self.assertEqual(calls["u-generic"], 3)
        self.assertIn("[skip: u-generic]", report)


class FetchUrlTests(unittest.TestCase):
    """fetch_url：urllib 优先，失败 fallback 到 curl。"""

    def test_valid_url_returns_text(self):
        """真实可达 URL 返回非空文本（网络 OK 时）。"""
        try:
            text = fetch_url("https://raw.githubusercontent.com/DandelionSprout/adfilt/master/BrowseWebsitesWithoutLoggingIn.txt", timeout=60)
        except Exception as exc:  # 本机网络可能不可达，跳过断言
            self.skipTest(f"network unavailable: {exc}")
        self.assertTrue(text.strip())


class ParseUpstreamTests(unittest.TestCase):
    """上游文件文本 -> 规则行：丢弃头部声明、! 注释与空行，保留规则行。"""

    def test_header_comments_and_blanks_are_dropped(self):
        text = (
            "[Adblock Plus 2.0]\n"
            "! Title: some upstream\n"
            "! Version: 20200101\n"
            "\n"
            "||example.com^\n"
            "\n"
            "! section comment\n"
            "##.ad-banner\n"
        )
        self.assertEqual(parse_upstream(text), ["||example.com^", "##.ad-banner"])

    def test_crlf_and_bom_are_normalised(self):
        text = "\ufeff[Adblock Plus 2.0]\r\n! Title: x\r\n||a.com^\r\n"
        self.assertEqual(parse_upstream(text), ["||a.com^"])

    def test_allowlist_lines_are_kept(self):
        text = "[Adblock Plus 2.0]\n@@||good.com^\n"
        self.assertEqual(parse_upstream(text), ["@@||good.com^"])

    def test_empty_text_yields_no_lines(self):
        self.assertEqual(parse_upstream(""), [])


if __name__ == "__main__":
    unittest.main()