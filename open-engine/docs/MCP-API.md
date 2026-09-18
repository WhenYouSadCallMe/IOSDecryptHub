# Open Engine MCP API

`host.NewServer` 返回可嵌入的 `http.Handler`。它不会自行监听端口或启动常驻进程，调用方应自行选择仅绑定 `127.0.0.1` 的 HTTP 服务，并在跨进程使用时配置 Bearer token。

## JSON-RPC

- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`，参数为 `{ "name": "query_events", "arguments": { ... } }`

为了方便本地脚本，Handler 也接受直接方法名：`query_events`、`find_values`、`trace_value`、`classify_response`、`summarize_flow`、`session_check`、`status`。

## 工具

### `query_events`

参数：`sessionId`、`flowId`、`requestId`、`type`、`operation`、`since`、`until`、`cursor`、`limit`、`projection`。`projection` 可选 `summary`、`stacks`、`crypto`、`network`、`full`；所有值字段通过 Redactor 输出。

### `trace_value`

参数：`start`/`valueId`、`direction`（`forward` 或 `backward`）、`maxDepth`。

### `find_values`

参数：`term`、`hash`、`role`、`dataType`、`sessionId`、`flowId`、`type`、`limit`、`projection`。搜索范围仅包括 `valueRefs` 和熵值/魔数/编码派生字段，不扫描原始参数文本，避免把凭据变成可搜索明文。

### `analyze_payload`

参数：`data`、`encoding`（可选 `hex`/`base64`/`utf8`）、`maxBytes`、`depth`。返回有界的 JSON/HTTP/压缩/编码/Protobuf/MessagePack 识别结果，压缩和编码内容最多递归两层。

### `analyze_macho`

参数：`path`。只读取本地 Mach-O/FAT 文件，返回架构、UUID、Segment 和虚拟地址；不会执行文件。

### `normalize_stack`

参数：`slide`（支持十进制或 `0x` 十六进制）和 `frames`。输出每个 frame 的 `idaAddress` 与可读归一化名称。

### `classify_response`

参数：`httpStatus`、`body`。结果会区分 transport/gateway/risk/business，并返回 reasons 和 confidence。

### `summarize_flow`

参数：`flowId`、`limit`。返回事件数量、类型、层级、操作和响应分类，适合先提供给 AI，再按需查询详情。

### `session_check`

参数：`event`。如果配置了 `SessionGuard`，返回 `allowed`、`age` 和拒绝原因；默认 fail-closed 的 freshness 策略由调用方配置。

### `generate_frida_script` / `generate_dylib_hook`

当前只返回 `record-only`、不可执行的观察计划，包含目标、采集字段、脱敏字段和审计步骤。它们不会生成注入、绕过或主动改写代码。

### `probe_mutation`

参数：`flowId`、`requestId`、`eventId`、`valueHash`、`field`、`operation`、`mutation`。返回带有 freshness、隔离目标、长度约束、回滚和响应分类要求的不可执行计划；Host 不会修改内存或发送请求。
