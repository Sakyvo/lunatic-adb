# lunatic-adb

自用 Adblock 规则聚合：GitHub Actions 每 12 小时拉取 16 个上游规则源，全局精确去重、按类别分段、段内排序后合成两份订阅文件，自动提交回本仓库。lite 与 origin 的区别是目标过滤引擎的**语法兼容性**（部分轻量浏览器无法解析 origin 特供源的复杂语法），不是规则数量——两版共享全部通用源，特供源只进各自版本。

## 订阅

| 版本 | raw | ghfast 镜像 |
|---|---|---|
| origin | <https://raw.githubusercontent.com/Sakyvo/lunatic-adb/main/lunatic-adb.txt> | <https://ghfast.top/https://raw.githubusercontent.com/Sakyvo/lunatic-adb/main/lunatic-adb.txt> |
| lite | <https://raw.githubusercontent.com/Sakyvo/lunatic-adb/main/lunatic-adb-lite.txt> | <https://ghfast.top/https://raw.githubusercontent.com/Sakyvo/lunatic-adb/main/lunatic-adb-lite.txt> |

- origin：uBlock Origin / AdGuard 等支持完整语法的引擎
- lite：VIA / Rian 等轻量引擎。**lite 会自动过滤 Via 读不了的语法**（uBO/AG 专属脚本/注入、特殊伪类、正则规则、`$redirect=`/`$rewrite=`/`$stealth=`/`$app=` 等），构建时经 `verify_lite` 自检保证 0 不支持、0 重复

## 类别

| 段落 | 内容 |
|---|---|
| main | 通用拦截规则主体（含 lingeringsound 与 BYD广告） |
| meta | 接口广告、横幅与弹窗 |
| privacy | EasyPrivacy 追踪器 |
| watermark | 视频水印遮盖 |
| login | 免登录浏览、"打开 App"提示 |
| cookie | Cookie 横幅与同意弹窗 |
| whitelist | `@@` 放行规则，固定最末段 |

## 上游来源

- [damengzhu/abpmerge](https://github.com/damengzhu/abpmerge) — main
- [jk278/Ad-J](https://github.com/jk278/Ad-J) — main
- [xinggsf/Adblock-Plus-Rule](https://github.com/xinggsf/Adblock-Plus-Rule) (mv.txt) — main
- [lingeringsound/adblock_auto](https://github.com/lingeringsound/adblock_auto) — main（特供：origin 版进 adblock_auto.txt，lite 版进 adblock_auto_lite.txt）
- [BYD广告](https://gist.githubusercontent.com/Sakyvo/a385daf67f65e09f7f7084baa7c9df87) — main
- [Sakyvo/Kyvo-Adblock](https://github.com/Sakyvo/Kyvo-Adblock) (Kyvo-M) — main
- [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) (jiekouAD) — meta
- [sbwml/halflife-list](https://github.com/sbwml/halflife-list) (ad-edentw) — meta
- [EasyPrivacy](https://easylist-downloads.adblockplus.org/easyprivacy.txt) — privacy
- [AdGuard Tracking Protection (uBO 变体)](https://filters.adtidy.org/extension/ublock/filters/3.txt) — privacy（仅 origin，体量过大不适轻量引擎）
- [runningcheese/RunningCheese-Firefox](https://github.com/runningcheese/RunningCheese-Firefox) (Adblock_Watermark) — watermark
- [DandelionSprout/adfilt](https://github.com/DandelionSprout/adfilt) (BrowseWebsitesWithoutLoggingIn) — login
- [Noyllopa/NoAppDownload](https://github.com/Noyllopa/NoAppDownload) — login
- [AdGuard Cookie Notices (uBO 变体)](https://filters.adtidy.org/extension/ublock/filters/18.txt) — cookie（接替已失效的 i-dont-care-about-cookies）
- [8680/GOODBYEADS](https://github.com/8680/GOODBYEADS) (allow.txt) — whitelist

感谢以上规则维护者。清单以 [`sources.json`](sources.json) 为准，增删上游只改该文件。
