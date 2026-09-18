# idh-core

这里是开放引擎的基础设施层，当前只包含：

- `IDHEvent`：统一事件契约，含 session/flow/request、ASLR slide、层级、置信度和证据。
- `IDHEventBus`：有序、同步发布；同步交付提供自然背压。
- `IDHProfileLoader`：JSON Profile schema 校验。
- `IDHHookRegistry`：声明式 Profile 的原子安装、启停、卸载和快照；它只维护状态，不执行 Hook。
- `IDHJSONLTransport`：事件 JSONL 落盘。

这些文件不实现注入、Inline Hook、反调试或常驻服务；它们可以在 macOS/Xcode
环境中作为后续授权 Agent 的基础编译单元。跨平台的熵值、去重、溯源和查询实现
位于 `open-engine/core`。
