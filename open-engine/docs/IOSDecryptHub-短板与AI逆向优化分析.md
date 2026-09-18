# IOSDecryptHub 短板与 AI 逆向优化分析

日期：2026-09-18
范围：公开的 IOSDecryptHub 仓库、已发现的 HTTP/MCP 包装、引擎二进制可见字符串，以及 `10086` 项目中的 iOS/H5 实际分析证据。

## 结论先行

IOSDecryptHub 的核心采集能力并不弱。它已经能记录 CommonCrypto、Security、OpenSSL/TLS、NSURLSession、文件、Keychain、系统调用、调用栈、镜像和 dump 等信息。

它对 AI 不够友好的主要原因不是“少了某一个 Hook”，而是：

```text
分类日志
  → 缺少统一事件身份
  → 缺少跨层关联
  → 缺少值来源图
  → 缺少语义查询和证据摘要
  → AI 只能手动翻日志、再猜哪个值属于哪个请求
```

因此新项目的优先级应是“事件标准化 + 关联 + 溯源 + MCP 语义层”，而不是先增加更多零散 Hook。

## 1. 证据与可信度

### 1.1 上游公开代码能确认的内容

上游 README 明确说明：

- `src/loader.m` 只读取启用名单并 `dlopen` 引擎。
- 真正的 Hook 引擎位于闭源 `decrypt_helper.dylib`。
- 管理器 App 负责启停、版本更新、回滚和重启目标 App。

参考：

- `../IosDecryptHub/README.md:24-31`
- `../IosDecryptHub/src/loader.m:1-5`

所以我们只能做行为等价的独立实现，不能把私有二进制当作可维护的源码基础。

### 1.2 引擎可见能力与“未暴露”能力

对 `decrypt_helper.dylib` 的字符串扫描能看到以下信号：

```text
CCCrypt / CCCryptor / CCHmac / CC_SHA*
SecItem* / SecKey*
SSL_read / SSL_write
NSURLSession / NSURLConnection
open / mmap / sysctl / dlopen / dlsym
callStack / CallStackFiltered
hook_import / hook_method / list_hooks
read_memory / search_memory
/api/mcp / tools/list / tools/call
localStorage
```

这证明引擎内部或 Web UI 至少考虑了 Hook、调用栈、内存、MCP 和 Storage 等能力；但字符串不是接口契约，不能把它们直接当成“已验证可用”。新项目必须为每项能力提供公开 schema、版本和测试。

### 1.3 Tunnel 当前暴露的能力

当前 Tunnel MCP 主要封装：

```text
logs / log_detail / logs_download
stats / config / diag / capture_summary
images / dump_status
probe / request / endpoints / capture_log
```

参考：`../IOSDecryptHub-Tunnel/iosdecrypthub_mcp.py:127-350` 和 `../IOSDecryptHub-Tunnel/MCP-配置说明.md:74-125`。

已发现但没有形成稳定语义工具的接口还包括：

```text
/api/files
/api/files/preview
/api/files/download
/api/symbols
/api/symbols?img=
/api/dump/download
/api/dump/image
/api/diag/download
/api/mcp
hook_import
hook_method
list_hooks
read_memory
search_memory
```

这使 AI 必须退回到一个通用的 `iosdecrypthub_request`，既不知道参数约束，也无法判断调用是否会改变设备状态。

## 2. 对 AI 逆向最重要的短板

### 短板 A：日志按类别和序号组织，而不是按一次分析流组织

当前接口以 `cat`、`seq`、`since`、`before` 取日志，再用另一个接口取详情。它适合人手查看，但不适合模型建立上下文。

AI 需要的不是“第 648 条 AES 日志”，而是：

```text
flow-17 / request-42
  ├─ Bridge 返回值
  ├─ Storage 写入
  ├─ SHA/MD5 派生
  ├─ AES 加密
  ├─ Header/Body 写入
  ├─ Network resume
  └─ Response
```

改进：每个事件必须有 `eventId`、`flowId`、`requestId`、`parentEventId`、时间戳、线程和进程信息，并支持按链路一次查询。

### 短板 B：有调用栈，但没有调用栈上下文

`log_detail` 已经能返回 `callStack`，这是上游的优点；问题是调用栈没有和“值从哪里来、去了哪里”组成关系。

需要同时返回：

```text
符号化栈帧
镜像 UUID / slide / offset
线程和队列
调用前后的参数摘要
同一值的 hash
父事件和后继事件
```

否则 AI 只能说“这里调用了 AES”，不能说“这个 AES 的结果后来进入了 x-token header”。

### 短板 C：缺少 Value Provenance（值溯源）

`10086` 中最耗人工的不是发现 AES，而是确认这些值是否属于同一条链：

```text
原生 Bridge
  → H5 token
  → Cookie/Storage
  → wasmParams / gr-risk-p3
  → placeOrder.do header/body
```

如果只看网络日志，`wtAcId`、`phone`、`gr-risk-p3`、`wasmParams` 看起来都是孤立字段；如果只看加密日志，又不知道密文被哪个请求消费。

改进：对每个值保存 `valueHash`、长度、类型、来源事件、变换事件、消费位置和有效期。默认不保存完整秘密。

### 短板 D：原生层、WebKit 层和 Storage 层没有统一时间线

`10086` 已经证明 Node shim 和真实 WKWebView 的指纹、Cookie 生命周期、WASM、Bridge 行为可能不同。仅抓 `NSURLSession` 或 `SSL_read/write` 无法解释 H5 请求的全部来源。

改进：

- Native 事件统一进入 EventBus。
- WKWebView JS adapter 发送同一 schema 的 JS 事件。
- `WKScriptMessageHandler`、Bridge 回调和 Storage 写入带同一 `flowId`。
- 对受控 App 记录 WebContent/Networking 子进程关系；不能把它宣传为消除 WebKit 隔离。

### 短板 E：响应只有原文，没有“层级判定”和证据理由

你的两个响应说明了这一点：

```json
{"resultCode":999,"msg":"活动太火爆啦～","data":null}
```

```json
{"code":-1,"data":{"explain":"SCORE_REFUSE","level":5,"risk":true},"message":"访问过于频繁"}
```

仅按文案搜索会把它们混为一类。AI 应收到：

```json
{
  "layer": "business_layer",
  "riskPassedByClientPredicate": true,
  "reason": ["data is null", "no data.risk", "resultCode=999"]
}
```

以及：

```json
{
  "layer": "risk_layer",
  "riskPassedByClientPredicate": false,
  "reason": ["code=-1", "data.risk=true", "explain=SCORE_REFUSE"]
}
```

这只能描述客户端可见证据，不能声称读到了服务端内部评分规则。

### 短板 F：MCP 是“接口转发”，不是“逆向分析工作流”

当前 `iosdecrypthub_request` 很灵活，但对 AI 来说信息不足：

- 不知道接口是只读还是修改状态。
- 不知道返回字段是否敏感。
- 不知道分页、游标和关联关系。
- 不知道下一步应该调用哪个接口。
- 一次容易返回过大的原始日志，浪费上下文窗口。

改进：保留底层通用请求，但在上面增加面向任务的只读工具和结构化资源；修改 Hook、清理日志、内存导出必须有显式确认和审计记录。

### 短板 G：没有“分析会话”和新鲜度模型

`10086` 中一次性 Bridge ticket、Cookie、设备 lid、风控 token 不能跨会话复用。AI 如果不知道值的有效期，就会把旧 HAR 当成当前事实。

每个采集会话应记录：

```text
sessionId
设备/系统/App 版本
目标 PID 和镜像快照
采集开始/结束时间
值的来源和 TTL
是否来自真实 WebView、沙箱或离线 fixture
```

MCP 默认只允许 AI 使用当前会话或明确标注为历史的证据。

### 短板 H：没有自动的“候选 Hook → 小窗口验证”闭环

AI 不应该一开始打开所有 Hook。更好的流程是：

```text
扫描镜像/selector/字符串
  → 生成候选 HookSpec
  → 只在 10~30 秒窗口启用
  → 采集并评分
  → 保留命中规则，卸载噪声规则
```

这样既降低性能开销，也让 AI 能解释“为什么选择这个 Hook”。

## 3. 应新增的插件和它们解决的问题

| 优先级 | 插件 | 核心输出 | 解决的问题 |
|---|---|---|---|
| P0 | `EventNormalizer` | 统一 Event Schema、时间线、线程/进程 | 日志不能关联 |
| P0 | `FlowCorrelator` | `flowId/requestId/parentEventId` | 加密与请求脱节 |
| P0 | `ValueProvenance` | 来源→变换→消费图 | AI 找不到各值 |
| P0 | `SessionGuard` | 会话、新鲜度、TTL、证据来源 | 误用旧 token/HAR |
| P0 | `MCPQuery` | 分页、投影、游标、只读语义工具 | 上下文浪费、接口难用 |
| P0 | `Redaction` | Hash/长度/预览/字段脱敏 | 秘密泄露到 AI |
| P1 | `StackSymbolicator` | Native/JS 栈帧、镜像 UUID、符号 | 只有栈文本，缺上下文 |
| P1 | `CryptoSemantic` | 算法/模式/key/iv/aad/tag/输入输出 | 只有 API 名称 |
| P1 | `NetworkTransaction` | 请求生命周期、Cookie、重定向、响应 | 请求链不完整 |
| P1 | `BridgeReturn` | 入参/返回值/Block/调用栈/WebView | 原生与 H5 断链 |
| P1 | `WebKitAdapter` | fetch/XHR/WASM/Storage/navigator | 抓不到 H5 真正生产值 |
| P1 | `StorageTrace` | Keychain、Defaults、SQLite、Cookie/Storage | 不知道值是否持久化 |
| P1 | `ResponseClassifier` | transport/risk/business/gateway 分类 | 文案造成误判 |
| P2 | `ProtocolDecoder` | Protobuf/gRPC/MessagePack 可插拔解码 | 只能看到二进制 |
| P2 | `MachOIndex` | 镜像、字符串、selector、xref、反汇编 | 候选函数定位慢 |
| P2 | `MemorySearch` | 受控目标的搜索/导出 | 无法验证运行时值 |
| P2 | `AIPlanner` | 候选 Hook、窗口实验、报告 | 需要人工编排 |

## 4. 统一事件应该长什么样

```json
{
  "schemaVersion": 1,
  "eventId": "e-123",
  "sessionId": "s-1",
  "flowId": "f-42",
  "requestId": "r-9",
  "parentEventId": "e-122",
  "timestamp": "2026-09-18T10:00:00.123Z",
  "target": {"bundleId":"redacted","pid":123,"tid":44,"image":"Foundation"},
  "layer": "native|webkit|storage|network|response",
  "operation": "CCCrypt|bridge.return|storage.set|request.resume",
  "arguments": [{"name":"key","hash":"sha256:...","length":16}],
  "result": {"type":"bytes","hash":"sha256:...","length":32},
  "nativeStack": [{"image":"App","symbol":"sendRequest+0x18"}],
  "jsStack": [],
  "valueRefs": [
    {"name":"x-token","hash":"sha256:...","role":"header","sourceEventId":"e-118"}
  ],
  "confidence": 0.98,
  "sensitivity": "masked",
  "evidence": {"source":"device-runtime","freshness":"current","ttlSeconds":120}
}
```

关键点：AI 查询默认只拿摘要和引用；只有在明确授权且满足脱敏策略时，才读取原始字节。

## 5. 面向 AI 的 MCP 设计

### 5.1 初始化与能力

```text
runtime_initialize
runtime_status
runtime_capabilities
session_start
session_stop
```

`runtime_capabilities` 必须明确：当前是自有 App、重签名、越狱还是模拟器，是否有 WebView adapter、符号和内存能力。

### 5.2 查询与溯源

```text
query_events(type, flowId, requestId, since, cursor, limit, projection)
get_event(eventId, detailLevel)
find_values(name, hash, role, sessionId)
trace_value(valueRef, direction, maxDepth)
explain_request(requestId)
compare_flows(leftFlowId, rightFlowId)
```

`projection` 允许 AI 只要 `summary`、`stacks`、`crypto` 或 `network`，避免每次拉取完整日志。

### 5.3 规则和实验

```text
profile_list
profile_validate
suggest_hooks(intent, scope)
apply_profile(profileId, windowSeconds)   # 必须显式确认
pause_profile(profileId)
export_fixture(flowId, redacted=true)
```

`suggest_hooks` 只生成候选规则；`apply_profile` 是有运行时影响的操作，必须返回审计 ID、过期时间和回滚方式。

### 5.4 分析报告

```text
explain_crypto_chain(requestId)
classify_response(eventId)
generate_protocol_skeleton(flowId, language)
export_analysis_report(flowId, format)
```

这些工具应返回“结论 + 证据事件 ID + 不确定性”，不能只返回一段没有出处的自然语言。

## 6. AI 最佳分析流程

```text
1. session_start
2. runtime_capabilities / target_snapshot
3. 只读采集一个基线流
4. AI 根据镜像、selector、URL、算法名生成候选 HookSpec
5. apply_profile 开启短时间窗口
6. EventNormalizer + FlowCorrelator 合并事件
7. ValueProvenance 建立值图
8. CryptoSemantic/NetworkTransaction 解释请求
9. ResponseClassifier 判断响应层
10. 导出脱敏 fixture 和 Python/Go 草稿
11. 由用户决定是否进行真实验证
```

AI 的回答格式应类似：

```text
请求 r-9 的 header `x-token` 来源：e-118
e-118 是 App::buildToken 的返回值，调用栈见 stack-7
随后在 e-121 进入 AES-CBC，算法证据完整度 0.96
e-123 将结果写入 NSURLRequest header
当前证据来自真实设备，TTL 120 秒；未保存完整密钥
```

而不是：

```text
我猜 x-token 可能是 AES-CBC。
```

## 7. 对 `10086` 问题的直接落地

`10086` 不是要写进核心引擎的业务分支，而是验证通用插件的 profile：

```text
BridgeReturn
  → COC token / wtAcId / ticket
  → Cookie / sessionStorage
  → const-id token + lid
  → wasmParams / gr-risk-p3
  → placeOrder.do
  → ResponseLayerClassifier
```

必须能回答：

1. `wtAcId` 是哪个 Bridge 调用返回的？
2. `phone` 是否来自当前 WebView 的 SSO token？
3. `gr-risk-p3` 与 `_zw_kvani5r` 是否同一轮注册得到？
4. `jsessionid-cmcc` 何时创建、是否随请求发送？
5. `wasmParams` 的 `bizToken` 与哪个值相同？
6. `resultCode=999/data=null` 和 `data.risk=true` 的证据差异是什么？

这六个问题都应该由 `trace_value`/`explain_request` 给出事件引用，而不是再人工翻 HAR。

## 8. 实施优先级

### P0：先让 AI 能正确“找值”

```text
EventNormalizer
FlowCorrelator
ValueProvenance
SessionGuard
Redaction
MCPQuery
```

### P1：补齐值的生产者和消费者

```text
BridgeReturn
WebKitAdapter
CryptoSemantic
NetworkTransaction
StorageTrace
StackSymbolicator
ResponseClassifier
```

### P2：提高定位深度和自动化程度

```text
MachOIndex
MemorySearch
ProtocolDecoder
AIPlanner
```

反调试、证书校验、环境伪装不应抢在 P0/P1 前面；它们既有平台限制，也不能解决“AI 不知道值来源”的主要问题。

## 9. 验收标准

一期完成后，使用一个授权测试 App 和脱敏 fixture，必须满足：

- 一次查询能得到完整 request flow，而不是手动拼多个分类日志。
- 任意网络字段可以反向追踪到最近的生产事件，或明确标记“未捕获来源”。
- 加密事件至少包含算法、输入/输出长度、摘要化 key/iv 和调用栈。
- Native、WebKit、Storage 事件可按 `flowId` 排序。
- 响应分类给出层级、规则命中项和证据事件 ID。
- MCP 默认分页、投影和脱敏，不把完整秘密放进模型上下文。
- Hook 规则可短时启用、自动过期、暂停和卸载。
- 历史会话与当前会话严格区分，过期 token 不被当成当前事实。

## 10. 当前判断

本项目不是简单“补几个 API”，而是给 IOSDecryptHub 增加一个分析语义层：

```text
IOSDecryptHub 的采集器
        +
公开事件/插件契约
        +
跨层 Flow/Value Provenance
        +
面向任务的 MCP/AI Planner
        =
更适合 AI 的通用 iOS 逆向工作台
```

下一步按 P0 顺序实现 `FlowCorrelator` 和 `ValueProvenance`，再把现有 EventBus/JSONL sink 接上查询接口；不会先把 CMCC 逻辑硬编码进核心。
