---
layout: post
title: 跟着ATT&CK学安全之initial access
excerpt: "跟着ATT&CK学安全之initial access"
categories: [ATT&CK]
comments: true
---
#### T1193 - Spearphishing Attachment
Spearphishing attachment是一种特殊类型的鱼叉攻击,它是通过邮件附件将病毒传播.在本案例中我们使用T1204来运行文件
##### 测试1 Download Phishing Attachment - VBScript
在允许宏指令的excel文件中可能包含了VBScript脚本,这个地址下载允许宏指令的excel文件
```bash
https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1193/bin/PhishingAttachment.xlsm
```
打开该excel便运行了VBScript脚本
#### 测试2 Word spawned a command shell and used an IP address in the command line
打开一个文档将会运行一个powershell

下载这个文档,并使用powershell运行它
```bash
https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1193/bin/PowerShell_IP_Doc.doc
```
```
Start-Process $PathToAtomicsFolder\T1193\bin\PowerShell_IP_Doc.doc
```
这个并没有成功,也没有在word中找到宏
#### Spearphishing Link 
通过在邮件中写入链接来下载病毒
#### Spearphishing via Service
攻击者使用个人webmail,社交媒体服务或者其他非企业的服务,发送病毒链接或者附件
#### Trusted Relationship
攻击者可能会破坏或以其他方式利用那些能够接触到目标受害者的组织(例如IT服务承包商、管理安全供应商、基础设施承包商)进行恶意软件下载等等
#### External Remote Services 
通过VPNs、Citrix等远程服务和其他访问机制从外部位置连接到企业内部网络资源
#### Exploit Public-Facing Application 
通过面向公网的有漏洞的应用进入
#### Replication Through Removable Media
通过可移动设备将恶意软件传入到系统中
#### Supply Chain Compromise
供应链攻击,产品在生产的链条中被攻击
#### Valid Accounts
攻击者通过获得账户发起攻击
#### Hardware Additions
通过引入硬件设备来开展攻击,例如

> passive network tapping https://ossmann.blogspot.com/2011/02/throwing-star-lan-tap.html, 

> man-in-the middle encryption breaking http://www.bsidesto.ca/2015/slides/Weapons_of_a_Penetration_Tester.pptx, 

> keystroke injection https://www.hak5.org/blog/main-blog/stealing-files-with-the-usb-rubber-ducky-usb-exfiltration-explained, 

> kernel memory reading via DMA https://www.youtube.com/watch?v=fXthwl6ShOg, 

> adding new wireless access to an existing network https://arstechnica.com/information-technology/2012/03/the-pwn-plug-is-a-little-white-box-that-can-hack-your-network/

#### Drive-by Compromise
Drive-by过程如下:
1. 用户浏览一个被攻击者控制的网站
2. 脚本被运行,通常是查看浏览器和插件的版本,查看是否是有漏洞的插件
3. 找到漏洞后,将利用代码放到浏览器中
4. 攻击者获取受害者的系统权限