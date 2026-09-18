# 阶段 0-5：Objective-C 基础契约验收

日期：2026-09-18

## 交付

- `src/idh-native/IDHMachO.*`：只读 dyld 镜像快照、UUID、header 地址和 ASLR slide。
- `src/idh-correlation/IDHAnalysisProfiler.*`：Objective-C 侧熵值、SHA-256、魔数和编码摘要。
- `src/idh-correlation/IDHStackSymbolizer.*`：用显式 slide 做 runtime → IDA 地址换算。
- `src/idh-observers/IDHObserver.*`：观察器生命周期和 record-only/extended/lab 模式门禁。
- Objective-C CI 脚本扩展到上述目录，并自动选择 `iphoneos` 或 `macosx` SDK。

## 仍未实现

这些契约没有安装 fishhook、Swizzle、Inline Hook、TLS 绕过、反调试或请求改写。真实
设备适配需要单独的签名环境、授权测试 App 和设备回归，不能由 Windows 本地测试替代。
