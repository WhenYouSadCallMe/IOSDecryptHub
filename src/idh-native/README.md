# idh-native

当前提供只读的 dyld/Mach-O 镜像快照和 ASLR 地址换算。它不安装 fishhook、不做
Inline Hook、不修改内存。后续若在授权签名环境增加原生适配器，必须沿用
`IDHEvent`、Profile 和 `IDHObserver` 契约，并单独通过设备回归。
