---
layout: post
title: 跟着ATT&CK学安全之persistence
excerpt: "跟着ATT&CK学安全之persistence"
categories: [ATT&CK]
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
#### T1176 - Browser Extensions
有些恶意软件是通过浏览器扩展的形式贮存在客户端上,而这些恶意

##### 测试1 Chrome (Developer Mode)
1. 打开chrome://extensions 并选择开发者模式
2. 加载已解压的扩展程序

##### 测试2 Chrome (Chrome Web Store)
1. 在chrome中打开`https://chrome.google.com/webstore/detail/minimum-viable-malicious/odlpfdolehmhciiebahbpnaopneicend`
2. 点击'Add to Chrome'
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