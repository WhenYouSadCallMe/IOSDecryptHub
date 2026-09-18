# IOSRuntimeAssistant

独立实现的 iOS 运行时分析平台。当前目录是阶段 0/1/2 基础和 AI 分析层的可运行实现，不依赖 IOSDecryptHub 的闭源引擎。

完整实施路线见上级目录的 [IOSRuntimeAssistant-实施路线图](../docs/IOSRuntimeAssistant-实施路线图.md)。

上游短板和面向 AI 的改造依据见 [IOSDecryptHub-短板与AI逆向优化分析](docs/IOSDecryptHub-短板与AI逆向优化分析.md)。

## 当前状态

- Event Schema v1
- 进程内 EventBus（带 context 背压）
- 声明式 HookSpec/Profile JSON 加载与校验
- 原生插件 ABI 草案（`agent/include`）
- 通用 Hook Registry：批量 profile 安装、启用/停用、卸载和快照
- `core/analysis`：熵值/魔数/编码识别、时间窗口去重、值溯源图、响应分层
- `core/analysis`：证据驱动的 Flow/Request/Value/Endpoint 关联，并保留关联原因与置信度
- `core/collect`：有上限的事件索引、按 Flow/Request/类型过滤、游标分页和安全投影；`Ingestor` 把会话保护、关联和去重串成一条入口
- `core/session`：会话 ID、时间窗口、证据 freshness/TTL 的 fail-closed 检查，避免把旧 cookie、bridge ticket 或风控结果混进新采集
- `host`：可嵌入的 MCP JSON-RPC Handler，提供 `query_events`、`trace_value`、`summarize_flow`、`classify_response`、`session_check` 和状态查询
- Windows 可执行的 Go 单元测试

后续 iOS Agent、Objective-C/Swift Hook 和 WebKit 适配会在相同事件契约上实现。

设计依据：`docs/IOSDecryptHub-短板与AI逆向优化分析.md`。这里先实现设备无关的分析层；任何真实设备适配必须在授权目标和可控签名环境中完成。

## 开发

```powershell
go test ./...
go vet ./...
```

当前不会连接真实设备，也不会执行短信、下单或其他业务写请求。

## MCP 嵌入示例

`host.NewServer` 只返回一个 `http.Handler`，不会自行监听端口，也不会启动常驻进程：

```go
index := collect.NewEventIndex(10000)
server := host.NewServer(host.Config{
    Index: index,
    BearerToken: os.Getenv("IDH_MCP_TOKEN"),
})
http.Handle("/mcp", server.Handler())
// 由调用方决定是否仅绑定 127.0.0.1，以及生命周期和认证策略。
```

`generate_frida_script` / `generate_dylib_hook` 目前只返回不可执行的
`record-only` 适配计划。仓库的 `AGENTS.md` 禁止新增实际 Hook、Inline Hook
和常驻 daemon；真实设备适配必须由授权的、已签名 Agent 在独立分支中实现。
