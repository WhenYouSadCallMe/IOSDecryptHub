# IOSRuntimeAssistant 实施路线图

这份路线图把用户提供的 IDH OPEN ENGINE v3.0 规格拆成可验收的阶段。当前仓库采用“分析层先行、设备适配后置”的策略：先让 AI 能可靠检索和解释事件，再在 macOS/Xcode、签名和授权测试 App 条件具备时接入观察器。

## 运行模式

| 模式 | 目标 | 当前状态 |
| --- | --- | --- |
| `record-only` | 记录事件、脱敏、索引、关联、溯源和报告 | 已实现主干 |
| `extended` | 在受控签名/越狱测试环境接入只读原生观察器 | 接口预留，未宣称完成 |
| `lab` | 实验室内调试和对抗性验证 | 不在默认构建中 |

## 阶段验收

### 阶段 0：工程边界与契约（已完成）

- 统一 Event Schema v1：session、flow、request、valueRefs、evidence、stack、ASLR 信息。
- 声明式 Profile 和 Hook Registry：校验、批量安装、启停、卸载、快照。
- 事件总线和 JSONL：有背压、有上限、有严格解析错误。

### 阶段 1：AI 分析层（已完成）

- 熵值、魔数、编码、SHA-256 元数据；不把原始值复制到分析字段。
- 时间窗口去重；首条事件保留，重复次数以 tag 表达。
- Value Provenance 图：前向/反向追踪。
- 响应分层：transport、gateway、risk、business；识别 `data.risk=true`、`SCORE_REFUSE` 和 `resultCode=999` 等证据。

### 阶段 2：关联、会话和 MCP（已完成）

- `FlowCorrelator` 按显式 flow、request、父事件、值哈希和端点关联，并输出原因/置信度。
- `SessionGuard` 检查 sessionId、活动会话、最大年龄、未来偏差、freshness 和 TTL，避免旧 HAR/cookie/bridge ticket 混入。
- `collect.Ingestor` 串联 Guard → Correlator → Annotation → Dedup → bounded index。
- 嵌入式 MCP JSON-RPC Handler：`query_events`、`trace_value`、`summarize_flow`、`classify_response`、`session_check` 和 `status`。

### 阶段 3：只读原生/ObjC 观察适配（下一步）

在 macOS/Xcode 和授权测试 App 上逐个实现以下观察器，并都输出 Event Schema v1：

1. Mach-O/dyld 镜像、ASLR slide、加载/卸载事件。
2. Objective-C 方法调用和 NSURLSession 生命周期的只读记录。
3. CommonCrypto、Security.framework、SQLite、Keychain 和 POSIX 文件访问的参数摘要。
4. WKWebView 的显式配置注入和 JSBridge 事件（只观察，不改写请求）。
5. Native/JS stack 的符号化与 `IDA_Address = runtime - slide` 计算。

每个适配器都要有：授权目标校验、采样/限流、脱敏配置、失败关闭、单元测试和设备回放样例。未满足这些条件前，不生成可执行的注入、inline hook、TLS 绕过或主动改写代码。

### 阶段 4：协议识别和报告（规划）

- HTTP/1.1、HTTP/2、WebSocket、Protobuf、gRPC、MessagePack 的只读重组。
- 基于证据的“加密输入 → 结果 → 网络字段”报告。
- 导出 Markdown/JSON/CSV 和 AI 提示上下文；默认只导出摘要和哈希。

### 阶段 5：受控实验能力（规划，默认关闭）

只有在明确授权的实验室目标、独立签名配置和回滚机制下评估主动探针。所有变异都必须显式确认、可审计、可回滚，并与生产/真实账号隔离。该阶段不会进入默认插件或公共 MCP。

## 与 CMCC iOS/H5 问题的对应关系

- 同一账号的 `resultCode=999` 业务响应与 `data.risk=true` 风控响应属于不同层，不能只按 HTTP 状态或 `code` 合并。
- 每次新采集都应创建新的 session，并在事件中携带证据来源和 freshness；旧 HAR 只能作为离线对照。
- `flowId` 贯穿 bridge、加密、请求和响应，`summarize_flow` 给 AI 先看层级/操作/证据，再按需展开脱敏字段。

## 明确不承诺

Windows 上不能验证 iOS 注入、签名、砸壳、TLS 绕过或真实设备网络路径；仓库也不新增常驻 daemon、inline hook、反调试绕过或请求篡改实现。相关目录只提供契约、计划和安全的 host-side 分析代码。
