# 阶段 0-6：持久化与 Record-only 接入验收

日期：2026-09-18

## 交付

- `src/idh-host/IDHSQLiteStore.*`：系统 SQLite 事件表、Flow/Request/Type 索引和有界查询。
- `src/idh-observers/IDHRecordOnlyObserver.*`：外部授权事件进入 EventBus；已有 WebKit Bridge 日志归一化为统一事件。
- CI 语法检查覆盖 `idh-native`、`idh-correlation`、`idh-observers`、`idh-host`。

## 边界

Record-only 适配器只接受调用方主动提供的事件。仓库不在这些文件中执行 Swizzle、fishhook、TLS Pinning 绕过、内存变异或跨进程读取。
