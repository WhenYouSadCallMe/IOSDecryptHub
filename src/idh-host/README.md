# idh-host

`IDHSQLiteStore` 是可选的主机侧 SQLite 落盘实现，使用系统 `sqlite3`，按
`flow_id`、`request_id` 和事件类型建立索引。它只存储 `IDHEvent` 的 JSON 表示，
调用方应在事件产生前完成脱敏；查询结果有上限，不把全量日志一次交给 AI。
