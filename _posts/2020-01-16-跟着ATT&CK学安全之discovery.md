---
layout: post
title: 跟着ATT&CK学安全之discovery
excerpt: "跟着ATT&CK学安全之discovery"
categories: [ATT&CK]
comments: true
---
#### T1087 - Account Discovery
##### linux上枚举所有账户
```bash
cat /etc/passwd
```
##### 查看sudoer权限账户
```bash
cat /etc/sudoers
```
##### View accounts with UID 0
```bash
grep 'x:0:' /etc/passwd
```
未完待续

#### T1124 - System Time Discovery
```
net time \\#{computer_name}
```
例如
```
net time \\localhost
```
或者
```
w32tm /tz
```
或者在powershell中
```
Get-Date
```
#### T1007 - System Service Discovery














---
layout: post
title: 跟着ATT&CK学安全之discovery
excerpt: "跟着ATT&CK学安全之discovery"
categories: [ATT&CK]
comments: true
---
#### T1087 - Account Discovery
##### linux上枚举所有账户
```bash
cat /etc/passwd
```
##### 查看sudoer权限账户
```bash
cat /etc/sudoers
```
##### View accounts with UID 0
```bash
grep 'x:0:' /etc/passwd
```
未完待续

#### T1124 - System Time Discovery
```
net time \\#{computer_name}
```
例如
```
net time \\localhost
```
或者
```
w32tm /tz
```
或者在powershell中
```
Get-Date
```
#### T1007 - System Service Discovery
