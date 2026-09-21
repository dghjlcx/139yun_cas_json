# 移动云盘 (139) CAS 工具集

利用移动云盘**服务端去重（秒传）机制**的"元数据代替实体文件"玩法：把文件的 SHA-256 指纹保存为 `.cas` 凭证（仅几百字节）或分享库 JSON，删除网盘实体文件释放空间；需要时凭指纹**零流量秒级恢复**文件、获取限时 CDN 直链。也可将本地/分享库的哈希数据批量秒传进自己的网盘。

> ⚠️ **风险必读**：本项目基于非官方逆向接口，移动云盘随时可能调整或关闭该机制；CAS/JSON 只是"指针"，**云端去重数据被清理后即永久失效**。请勿作为唯一备份。仅供个人学习研究，勿用于传播侵权内容。

## 文件清单

| 文件 | 类型 | 功能 |
|---|---|---|
| `yun139_cas.user.js` | **油猴脚本（核心，推荐）** | 网页端三合一：导出 CAS / 恢复 CAS（支持分享库JSON直导） / 本地生成 CAS |
| `cas139_check.py` | Python CLI | CAS 检测、秒传恢复、CDN 直链获取与到期解析、删除验证；账号密码自动登录 |
| `cas139_gen.py` | Python CLI | 本地文件/文件夹批量生成 CAS（C 哈希 ~600MB/s）；`--cloud` 模式零下载抓取云端已有文件哈希 |
| `json2cas.py` | Python CLI | 分享库 JSON 批量转 CAS（文件夹批处理、目录镜像、SQLite 去重库） |

## 一、油猴脚本（功能最全）

**安装**：安装 [Tampermonkey](https://www.tampermonkey.net/) → 新建脚本 → **清空模板全文粘贴**本文件 → 保存 → 打开 [yun.139.com](https://yun.139.com) → **随便点一个文件夹**（自动捕获登录态，右下角出现面板）。

### 页签 1：导出 CAS

把网盘文件批量导出为 CAS 凭证或分享库 JSON：

1. 目录树勾选文件夹（可多选、跨位置，勾选=整个子树）
2. 可选**格式过滤**（如 `mkv,mp4,iso`，留空=全部）
3. 选择**导出格式**：
   - **CAS 打包**：`139_cas_*.zip`，内部按云端目录结构镜像，可直接导回恢复
   - **分享库 JSON**：`139_share_*.json`，单文件数组，每条 `{name(全路径), size, sha256}` 三要素，可回流分享（别人用同款插件"保留完整路径"模式即可 1:1 还原）
4. 点导出 → ZIP/JSON 自动下载

### 页签 2：恢复 CAS

把 CAS / ZIP / JSON / 整个文件夹秒传恢复到网盘：

1. **恢复到目录**：目录树单选目标位置（默认根目录）
2. **添加文件**：支持 `.cas`（单/多选）、`.zip`（自动解包，含目录结构）、`.json`（分享库直导，无需先转 CAS）、**添加文件夹**（webkitdirectory 整目录导入，保留子目录结构）
3. **JSON 目录模式**（仅 JSON 导入时）：
   - 按 JSON 文件名建文件夹（每部剧一个文件夹，默认）
   - 保留条目完整路径（自动剥共同前缀，适合路径信息完整的库）
   - 保留末尾 1 级 / 2 级目录（剧集推荐"末尾1级"）
4. **剥掉最外层公共目录**开关：手动打包多裹了废目录时勾选；**插件导出 ZIP 再导入的往返场景请取消勾选**（1:1 还原）
5. 点恢复 → 逐文件彩色日志：`✓ 秒传成功` / `= 已存在同名` / `✗ 数据不在云端`（含目录前缀），300ms 限速

### 页签 3：本地生成

本地文件/文件夹直接在浏览器里算 SHA-256 生成 CAS：

1. 选择文件或文件夹（Chrome/Edge 走系统级目录选择器）
2. 选择**输出目录**（File System Access API 直接写入本地目录）或不选（打包 ZIP 下载）
3. 可关"保持目录结构"（默认开，镜像原目录树）
4. 哈希在 **Web Worker** 中计算（32MB×2 流水线，不卡页面、内存封顶约 64MB、进度百分比实时显示），纯本地运算不上传任何数据

## 二、Python 工具

无需第三方依赖，Python 3.8+。凭证三选一填在脚本顶部：账号+密码（自动登录，推荐）/ `AUTH_139`（OpenList 139 `personal_new` 驱动同款 token）/ 本地缓存（自动）。

```bash
# cas139_check.py —— 检测/恢复/取址
python cas139_check.py 某文件.cas                 # 检测可恢复性 (FileDataExists)
python cas139_check.py 某文件.cas --url           # 秒传恢复 -> CDN直链+到期时间
python cas139_check.py 某文件.cas --force         # 跳过检测直接恢复
python cas139_check.py 目录 -r --url --keep       # 批量恢复并保留文件

# cas139_gen.py —— 生成 CAS
python cas139_gen.py "D:\Downloads" -r            # 本地批量（C实现哈希, 远快于浏览器）
python cas139_gen.py --cloud / -r out             # 云端模式: 零下载抓已入云文件的哈希

# json2cas.py —— 分享库JSON转CAS
python json2cas.py                                # 交互: 输入文件夹->全部JSON批量转换
python json2cas.py 文件夹 [输出] [-r]             # 输出默认 文件夹/cas_out, .zip结尾打ZIP
```

json2cas 特性：name 取 JSON 文件名+条目扩展名（剧集保留条目原名）、按 JSON 目录镜像结构、**SQLite 去重库**（`cas_records.db`，sha256 主键跨批次去重）、Windows 文件名加固（非法字符/尾随空格点/保留名）、全批次统一时间戳、坏文件容错不中断、WAL+按文件提交（大批量提速明显）。

## 三、分享库 JSON 格式与可用性判断

```json
[{"name": "剧集/三体 (2022)/E01.mkv", "size": 300, "sha256": "ab…"}]
```

**拿到库先验货**（记事本打开任一 JSON 看 sha256 长度）：

| sha256 长度 | 结论 |
|---|---|
| **64 位 hex** | ✅ 可用（139 秒传唯一凭证） |
| 32 位 hex | ❌ MD5 或被截断的 SHA256，**无法补全，不可用**（实测服务端算法白名单只有 SHA256） |
| 全零 | ❌ 占位符，工具会自动拦截 |

**命中率提醒**：秒传能否成功取决于内容**是否真的在 139 的去重库里**（有没有人传过）。分享库=社区哈希池，热门资源命中率高、冷门可能全灭。建议先小批量试恢复再决定整库操作。

## 四、典型工作流

```
占用空间玩法:
  导出 CAS/JSON -> 删除网盘实体文件(清空回收站) -> 空间释放
  -> 需要时 恢复 CAS --url -> 秒传恢复 -> 取直链 -> (可选)删除验证

分享库入库:
  下载分享库 -> 插件"恢复CAS"页签直接导入JSON(选目录模式) -> 秒传建库
  或 json2cas.py 转CAS -> cas139_check.py 批量恢复

本地资源造库:
  cas139_gen.py 本地/云端生成 CAS -> 自用或导出JSON分享
```

## 五、常见问题（FAQ）

**Q: 恢复报 `04000002 算法名不符合标准`？**
32 位哈希按 MD5 强传被服务端白名单拒绝。该库是提取工具截断的，无解，只能找完整哈希。

**Q: 恢复报 `04000002 目录类型不支持当前命名模式`？**
建目录不能带 `fileRenameMode` 参数（仅文件可用）。旧版脚本有此 bug，请更新到最新版。

**Q: ZIP 导入后没有目录结构/文件名乱码？**
国产压缩软件（好压/360压缩）用反斜杠存路径、Windows 资源管理器打 ZIP 中文名是 GBK——本工具已兼容两种（反斜杠归一化 + 按 ZIP 标志位自动 GBK/UTF-8 解码）。仍异常请用插件自带导出功能做往返。

**Q: 插件导出 ZIP 再导入，结构全平了？**
勾选框"剥掉最外层公共目录"默认会剥掉共享根——往返导入请取消勾选。

**Q: 单个 JSON 导入时剧名文件夹没建出来？**
旧版公共前缀剥离误伤，新版已修复（jsonname/末尾N级模式免疫剥离）。

**Q: `✗ 数据不在云端`？**
该内容没人传进过 139，分享库的哈希指向虚空。无法恢复。

## 六、原理简述

```
导出: /file/list 响应 items[].contentHash 免费回吐整文件 SHA-256
恢复: POST /file/create {contentHash, contentHashAlgorithm:"SHA256", size, parentFileId}
        → rapidUpload=true 秒传成功(零流量) / partInfos=未命中
建目录: POST /file/create {type:"folder"} (不可带 fileRenameMode)
取址:  POST /file/getDownloadUrl {fileId} → 302 解析 CDN 直链
签名:  Mcloud-Sign = MD5(MD5(b64(逐字符排序(encodeURIComponent(body)))) + MD5(ts:rand))
登录:  mail.10086.cn SSO 三步 (SHA1密码→artifact→AES加密thirdlogin)
```

纯 Python/JS 实现全部密码学原语（AES-128/192/256、MD5、SHA-256、HMAC-SHA1），零依赖。

## 七、验证

- SHA-256：FIPS 向量 + 填充边界 + 亿字节级与 hashlib 交叉验证
- AES：FIPS-197 三组密钥长度；HMAC：RFC2202；MD5：标准向量
- 直链到期解析：AWS4 签名 URL（X-Amz-Date + X-Amz-Expires）精确到秒
- ZIP：store/deflate、UTF-8/GBK 文件名、反斜杠路径全兼容（双向验证）

## 免责声明

- 所有接口行为均为非官方逆向结果，随时可能失效，以实测为准
- 请遵守移动云盘服务条款，控制 API 调用频率（脚本已内置限速）
- 使用本工具产生的一切后果由使用者自行承担

## 致谢

- [OpenList](https://github.com/OpenListTeam/OpenList) / AList 生态 `139` 与 `189pc` 驱动源码（签名与接口参数对齐来源）
- 天翼云 CAS 生态（`.cas` 文件格式设计）
- 115 / 阿里云盘 / Google Drive 秒传机制研究社区（哈希体系对照）
