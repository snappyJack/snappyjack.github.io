---
layout: post
title: 跟着ATT&CK学安全之lateral-movement
excerpt: "跟着ATT&CK学安全之lateral-movement"
categories: [ATT&CK]
comments: true
---
#### Application Deployment Software
攻击者可以通过企业管理员账号进行软件下发,来进行横向移动
#### T1037 - Logon Scripts
通过修改远程的Logon Scripts脚本来进行横向移动
##### 测试1 使用调度系统添加Logon自启动
```
schtasks /create /tn "T1037_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
schtasks /create /tn "T1037_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
```
#### T1075 - Pass the Hash
这项技术不需要攻击者
#### T1105 - Remote File Copy
##### 测试1 rsync remote file copy (push)
平台:linux
`rsync -r #{local_path} #{username}@#{remote_host}:#{remote_path}`
##### 测试2 rsync remote file copy (pull)
平台:linux
`rsync -r #{username}@#{remote_host}:#{remote_path} #{local_path}`
##### 测试3 scp remote file copy (push)
平台:linux
`scp #{local_file} #{username}@#{remote_host}:#{remote_path}`
##### 测试4 scp remote file copy (pull)
平台:linux
`scp #{username}@#{remote_host}:#{remote_file} #{local_path}`
方法很多,未完待续

#### T1076 - Remote Desktop Protocol