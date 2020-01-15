---
layout: post
title: 跟着ATT&CK学安全之defense-evasion
excerpt: "跟着ATT&CK学安全之defense-evasion"
categories: [ATT&CK]
comments: true
---
#### T1009 - Binary Padding
通过向binary末尾来绕过基于hash的黑名单校验,同时较大的文件也可以绕过一些安全产品的检测

测试平台:macOS, Linux,其中count代表填充多少个字节
```bash
dd if=/dev/zero bs=1 count=10 >> filename
```
#### T1090 - Connection Proxy
不直接连接受害者的电脑而是使用代理,现成的工具包括[HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap.
##### 测试1 Connection Proxy
平台:macOS, Linux

让该终端走某个代理
```
export http_proxy=http://127.0.0.1:7777
```
清除
```
unset http_proxy
```
##### 测试2 portproxy reg key
平台:windows

在终端修改注册表键`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4`

这个未完待续
#### T1143 - Hidden Window
通过在powershel中添加"-WindowStyle Hidden"参数来隐藏窗口
```bash
Start-Process notepad.exe -WindowStyle Hidden
```

