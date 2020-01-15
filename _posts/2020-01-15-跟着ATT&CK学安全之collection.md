---
layout: post
title: 跟着ATT&CK学安全之collection
excerpt: "跟着ATT&CK学安全之collection"
categories: [未完待续]
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
#### T1056 - Input Capture