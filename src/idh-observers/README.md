# idh-observers

这里定义观察器生命周期和运行模式协调器。当前只允许 `record-only` 观察器启动；
`extended`/`lab` 必须由明确授权、已签名的独立适配器接入。仓库不会在此目录
新增 TLS 绕过、反调试、请求篡改或隐藏注入逻辑。

`IDHRecordOnlyObserver` 接收外部授权采集器提供的 `IDHEvent`，交给 EventBus；
`IDHEventFromWebKitBridgeMessage` 只做已有 JSBridge 日志的 Schema 归一化，不注入
脚本、不跨进程读取 WebKit。
