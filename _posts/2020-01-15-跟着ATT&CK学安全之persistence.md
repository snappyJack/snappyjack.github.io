---
layout: post
title: 跟着ATT&CK学安全之persistence
excerpt: "跟着ATT&CK学安全之persistence"
categories: [未完待续]
comments: true
---
#### T1050 - New Service

##### 测试1,创建一个新的服务
```
sc.exe create #{service_name} binPath= #{binary_path}
sc.exe start #{service_name}
```
就是
```

```
清除痕迹
```
sc.exe stop #{service_name}
sc.exe delete #{service_name}
```
#### T1100 - Web Shell
通过使用webshell来维持控制,demo略
#### Valid Accounts
通过已有的账号来维持控制