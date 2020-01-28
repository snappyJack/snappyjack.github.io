---
layout: post
title: 跟着ATT&CK学安全之collection
excerpt: "跟着ATT&CK学安全之collection"
categories: [ATT&CK]
comments: true
---
#### T1123 - Audio Capture
##### 使用AudioDeviceCmdlets
github地址:`https://github.com/frgnca/AudioDeviceCmdlets`

打开powershell,在source目录下运行`Install-Module -Name AudioDeviceCmdlets`

#### T1119 - Automated Collection

##### Automated Collection PowerShell
在powershell下收集doc文件到指定目录下
```bash
Get-ChildItem -Recurse -Include *.doc | % {Copy-Item $_.FullName -destination c:\temp}
```
##### Recon information for export with Command Prompt
通过bash收集一些系统信息
```bash
sc query type=service > %TEMP%\T1119_1.txt
doskey /history > %TEMP%\T1119_2.txt
wmic process list > %TEMP%\T1119_3.txt
tree C:\AtomicRedTeam\atomics > %TEMP%\T1119_4.txt
```
清除
```
del %TEMP%\T1119_1.txt
del %TEMP%\T1119_2.txt
del %TEMP%\T1119_3.txt
del %TEMP%\T1119_4.txt
```
还有一些bash的脚本,没有技术含量,在此不再列举
#### T1005 - Data from Local System
平台:macOS
```
cd ~/Library/Cookies
grep -q "#{search_string}" "Cookies.binarycookies"
```
### T1113 - Screen Capture
###### 测试1 X Windows Capture
```
xwd -root -out #{output_file}
xwud -in #{output_file}
```
因该可以
###### 测试2 Import
```
import -window root
```
应该可以
### T1114 - Email Collection
红队可以从用户系统中获取包含电子邮件数据的文件，例如Outlook存储或缓存文件.pst和.ost。还可以利用用户的凭据并直接与Exchange服务器进行交互，以从网络内部获取信息.或者访问面向外部的Exchange服务或Office 365，以使用凭据或访问令牌访问电子邮件,MailSniper这个工具可用于在Microsoft Exchange环境中的电子邮件中搜索特定术语（密码，内部情报，网络体系结构信息等）。它可以用作非管理用户来搜索自己的电子邮件，也可以用作管理员来搜索域中每个用户的邮箱。

红队还可能滥用电子邮件转发规则来监视受害者的活动.组织内的任何用户或管理员（或具有有效凭据的对手）都可以创建规则收件箱规则
，以自动将所有接收到的邮件转发给另一个收件人，根据发件人将电子邮件转发到其他位置
###### 测试1 T1114 Email Collection with PowerShell
```
powershell -executionpolicy bypass -command $PathToAtomicsFolder\T1114\Get-Inbox.ps1 -file #{output_file}
```
应该可以