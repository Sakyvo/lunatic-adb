# lunatic-adb

自用 Adblock 规则聚合：GitHub Actions 每 12 小时拉取 13 个上游规则源，全局精确去重、按类别分段、段内排序后合成两份订阅文件，自动提交回本仓库。lite 与 origin 的区别是目标过滤引擎的**语法兼容性**（部分轻量浏览器无法解析 origin 特供源的复杂语法），不是规则数量——两版共享全部通用源。

## 订阅

| 版本 | raw | jsDelivr CDN |
|---|---|---|
| origin | <https://raw.githubusercontent.com/Sakyvo/lunatic-adb/main/lunatic-adb.txt> | <https://cdn.jsdelivr.net/gh/Sakyvo/lunatic-adb@main/lunatic-adb.txt> |
| lite | <https://raw.githubusercontent.com/Sakyvo/lunatic-adb/main/lunatic-adb-lite.txt> | <https://cdn.jsdelivr.net/gh/Sakyvo/lunatic-adb@main/lunatic-adb-lite.txt> |

- origin：uBlock Origin / AdGuard 等支持完整语法的引擎
- lite：VIA / Rian 等轻量引擎

## 类别

| 段落 | 内容 |
|---|---|
| 主要 | 通用拦截规则主体 |
| 特供 | 单一版本专属源（lingeringsound origin / lite） |
| 广告横幅 | 接口广告、横幅与弹窗 |
| 隐私 | EasyPrivacy 追踪器 |
| 水印 | 视频水印遮盖 |
| 登录信息 | 免登录浏览、"打开 App"提示 |
| Cookie | Cookie 横幅与同意弹窗 |
| 防误杀白名单 | `@@` 放行规则，固定最末段 |

## 上游来源

- [damengzhu/abpmerge](https://github.com/damengzhu/abpmerge) — 主要
- [jk278/Ad-J](https://github.com/jk278/Ad-J) — 主要
- [xinggsf/Adblock-Plus-Rule](https://github.com/xinggsf/Adblock-Plus-Rule) (mv.txt) — 主要
- [lingeringsound/adblock_auto](https://github.com/lingeringsound/adblock_auto) — 特供（origin / lite）
- [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) (jiekouAD) — 广告横幅
- [sbwml/halflife-list](https://github.com/sbwml/halflife-list) (ad-edentw) — 广告横幅
- [EasyPrivacy](https://easylist-downloads.adblockplus.org/easyprivacy.txt) — 隐私
- [runningcheese/RunningCheese-Firefox](https://github.com/runningcheese/RunningCheese-Firefox) (Adblock_Watermark) — 水印
- [DandelionSprout/adfilt](https://github.com/DandelionSprout/adfilt) (BrowseWebsitesWithoutLoggingIn) — 登录信息
- [Noyllopa/NoAppDownload](https://github.com/Noyllopa/NoAppDownload) — 登录信息
- [i-dont-care-about-cookies](https://www.i-dont-care-about-cookies.eu/abp/) — Cookie
- [8680/GOODBYEADS](https://github.com/8680/GOODBYEADS) (allow.txt) — 防误杀白名单

感谢以上规则维护者。清单以 [`sources.json`](sources.json) 为准，增删上游只改该文件。
