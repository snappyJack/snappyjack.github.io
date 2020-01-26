---
layout: post
title: 跟着ATT&CK学安全之discovery
excerpt: "跟着ATT&CK学安全之discovery"
categories: [ATT&CK]
comments: true
---
### T1087 - Account Discovery
对于windows,可使用`net user`,`net group`,`net localgroup`.使用Net工具集或者dsquery.提供所有者/用户的发现:红队想查看主要的用户,当前登陆的用户,通常红队使用Credential Dumping来检索用户名称

对于linux ,使用`/etc/passwd`来查看用户
###### 测试1 linux上枚举所有账户
```bash
cat /etc/passwd
```
成功复现
###### 测试2 查看sudoer权限账户
```bash
cat /etc/sudoers
```
成功复现
###### 测试3 View accounts with UID 0
```bash
grep 'x:0:' /etc/passwd
```
成功复现
###### 测试4 List opened files by user
```
lsof -u $username
```
成功复现
###### 测试5 Show if a user account has ever logger in remotely
```
lastlog
```
成功复现
###### 测试6 Enumerate users and groups
```
groups
id
```
成功复现
###### 测试7 Enumerate all accounts
```
net user
net user /domain
dir c:\Users\
cmdkey.exe /list
net localgroup "Users"
net localgroup
```
win10成功复现
###### 测试8 Enumerate all accounts via PowerShell
```
net user
net user /domain
get-localuser
get-localgroupmember -group Users
cmdkey.exe /list
ls C:/Users
get-childitem C:\Users\
dir C:\Users\
get-aduser -filter *
get-localgroup
net localgroup
```
win10成功复现
###### 测试9 Enumerate logged on users
```
query user
```
win10成功复现
#### T1124 - System Time Discovery
```
net time \\#{computer_name}
```
例如
```
net time \\localhost
```
或者
```
w32tm /tz
```
或者在powershell中
```
Get-Date
```
#### T1010 - Application Window Discovery
红队可以使用如下进行应用程序列表的查看
###### 测试1 List Process Main Windows - C# .NET
使用源码编译一个exe然后查看运行的process
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -out:#{output_file_name} T1010.cs
#{output_file_name}
```
还挺好用的

win10成功复现
### T1217 - Browser Bookmark Discovery
###### 测试1 List Mozilla Firefox Bookmark Database Files on Linux
```
find / -path "*.mozilla/firefox/*/places.sqlite" -exec echo {} >> /tmp/firefox-bookmarks.txt \;
```
回去用我的笔记本试一下
###### 测试2 List Google Chrome Bookmarks on Windows with powershell
```
where.exe /R C:\Users\ Bookmarks
```
win10成功复现
###### 测试3 List Google Chrome Bookmarks on Windows with command prompt
```
where /R C:\Users\ Bookmarks
```
win10成功复现
### T1482 - Domain Trust Discovery
关于域信任关系：在同一个域内,成员服务器根据Active Directory中的用户账号,可以很容易地把资源分配给域内的用户.但一个域的作用范围毕竟有限,有些企业会用到多个域,那么在多域环境下,我们该如何进行资源的跨域分配呢？也就是说,我们该如何把A域的资源分配给B域的用户呢？一般来说,我们有两种选择,一种是使用镜像账户.也就是说,我们可以在A域和B域内各自创建一个用户名和口令都完全相同的用户账户,然后在B域把资源分配给这个账户后,A域内的镜像账户就可以访问B域内的资源了

红队通过收集域信任关系从而进行横向移动.通过调用DSEnumerateDomainTrusts() Win32 API,来进行枚举
###### 测试1 Windows - Discover domain trusts with dsquery
```
dsquery * -filter "(objectClass=trustedDomain)" -attr *
```
制定的域不存在，应该可以复现
###### 测试2 Windows - Discover domain trusts with nltest
使用nltest发现信任的域名,这个技术曾被Trickbot病毒家族使用
```
nltest /domain_trusts
```
win10成功复现
###### 测试3 Powershell enumerate domains and forests
```
Get-NetDomainTrust
Get-NetForestTrust
Get-ADDomain
Get-ADGroupMember Administrators -Recursive
```
**没有复现成功**
### T1083 - File and Directory Discovery
红队可以枚举文件和目录进行信息收集,通常用`tree`和`dir`命令,或者使用window的api,对于linux,使用`ls``find`和`locate`来收集
###### 测试1 File and Directory Discovery
```
dir /s c:\ >> %temp%\download
dir /s "c:\Documents and Settings" >> %temp%\download
dir /s "c:\Program Files\" >> %temp%\download
dir /s d:\ >> %temp%\download
dir "%systemdrive%\Users\*.*" >> %temp%\download
dir "%userprofile%\AppData\Roaming\Microsoft\Windows\Recent\*.*" >> %temp%\download
dir "%userprofile%\Desktop\*.*" >> %temp%\download
tree /F >> %temp%\download
```
win10成功复现
###### 测试2 File and Directory Discovery
在powershell中运行
```
ls -recurse
get-childitem -recurse
gci -recurse
```
win10成功复现
###### 测试3  Nix File and Diectory Discovery
```
ls -a > allcontents.txt
ls -la /Library/Preferences/ > detailedprefsinfo.txt
file */* *>> ../files.txt
find . -type f
ls -R | grep ":$" | sed -e 's/:$//' -e 's/[^-][^\/]*\//--/g' -e 's/^/ /' -e 's/-/|/'
locate *
which sh
```
成功复现
###### 测试4 Nix File and Directory Discovery
```
cd $HOME && find . -print | sed -e 's;[^/]*/;|__;g;s;__|; |;g' > /tmp/loot.txt
cat /etc/mtab > /tmp/loot.txt
find . -type f -iname *.pdf > /tmp/loot.txt
find . -type f -name ".*"
```
成功复现
### T1046 - Network Service Scanning
###### 测试1 Port Scan
在linux中
```
for port in {1..65535};
do
  echo >/dev/tcp/192.168.1.1/$port && echo "port $port is open" || echo "port $port is closed" : ;
done
```
成功复现
###### 测试2 Port Scan Nmap
```
nmap -sS #{network_range} -p #{port}
telnet #{host} #{port}
nc -nv #{host} #{port}
```
成功复现
### T1135 - Network Share Discovery
对于windows,通常使用SMB协议进行文件分享,`net view \remotesystem`可以用来查询远程及其是否开启了远程共享.也可以使用`net share`.查看本地开启的共享服务,红队可以根据这个进行更进一步的横向移动
###### 测试1 Network Share Discovery
```
df -aH
smbutil view -g //#{computer_name}
showmount #{computer_name}
```
成功复现
###### 测试2 Network Share Discovery command prompt
```
net view \\#{computer_name}
例如
net view localhost
```
win10成功复现
### T1040 - Network Sniffing
这个没什么说的,就是抓流量
### T1201 - Password Policy Discovery
红队根据获取企业网络中的密码规则,从而减小爆破的量.对于windows,可以使用`net accounts`和`net accounts /domain`,对于linux,使用`chage -l`和`cat /etc/pam.d/common-password`
###### 测试1 Examine password complexity policy - Ubuntu
```
cat /etc/pam.d/common-password
```
应该可以
###### 测试2 Examine password complexity policy - CentOS/RHEL 7.x
```
cat /etc/security/pwquality.conf
```
成功复现
###### 测试3 Examine password complexity policy - CentOS/RHEL 6.x
```
cat /etc/pam.d/system-auth
cat /etc/security/pwquality.conf
```
成功复现
###### 测试4 Examine password expiration policy - All Linux
```
cat /etc/login.defs
```
成功复现
###### 测试5 Examine local password policy - Windows
```
net accounts
```
win10成功复现
###### 测试6 Examine domain password policy - Windows
```
net accounts /domain
```
win10成功复现
### T1069 - Permission Groups Discovery
红队通过查找本地或者远程的组来获取权限,对于windows,使用`net group /domain`和`net localgroup`来查看,对于linux,使用`groups`和`ldapsearch`
###### 测试1 Permission Groups Discovery
```
dscacheutil -q group
dscl . -list /Groups
groups
```
成功复现
###### 测试2 Basic Permission Groups Discovery Windows
```
net localgroup
net group /domain
```
成功复现
###### 测试3 Permission Groups Discovery PowerShell
在powershell中运行
```
get-localgroup
get-ADPrincipalGroupMembership #{user} | select name
```
win10成功复现
###### 测试4 Elevated group enumeration using net group
```
net group /domai 'Domain Admins'
net groups 'Account Operators' /doma
net groups 'Exchange Organization Management' /doma
net group 'BUILTIN\Backup Operators' /doma
```
没有成功复现
### T1057 - Process Discovery
###### 测试1 Process Discovery - ps
linux中
```
ps >> #{output_file}
ps aux >> #{output_file}
```
成功复现
###### 测试2 Process Discovery - tasklist
windows中
```
tasklist
```
win10成功复现
### T1018 - Remote System Discovery
###### 测试1 Remote System Discovery - net
```
net view /domain
net view
```
win10成功复现
###### 测试2 Remote System Discovery - net group Domain Computers
```
net group "Domain Computers" /domain
```
应该可以
###### 测试3 Remote System Discovery - nltest
```
nltest.exe /dclist:#{target_domain}
```
应该可以
###### 测试4 Remote System Discovery - ping sweep
```
for /l %i in (1,1,254) do ping -n 1 -w 100 192.168.1.%i
```
win10成功复现
###### 测试5 Remote System Discovery - arp
```
arp -a
```
win10成功复现
###### 测试6 Remote System Discovery - arp nix
```
arp -a | grep -v '^?'
```
成功复现
###### 测试7 Remote System Discovery - sweep
```
for ip in $(seq 1 254); do ping -c 1 192.168.1.$ip; [ $? -eq 0 ] && echo "192.168.1.$ip UP" || : ; done
```
成功复现
###### 测试8 Remote System Discovery - nslookup
powershell中运行
```
$localip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$pieces = $localip.split(".")
$firstOctet = $pieces[0]
$secondOctet = $pieces[1]
$thirdOctet = $pieces[2]
foreach ($ip in 1..255 | % { "$firstOctet.$secondOctet.$thirdOctet.$_" } ) {cmd.exe /c nslookup $ip}
```
win10成功复现
### T1518 - Software Discovery
###### 测试1 Find and Display Internet Explorer Browser Version
```
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer" /v svcVersion
```
win10成功复现
###### 测试2 Applications Installed
```
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
```
win10成功复现
### T1082 - System Information Discovery
###### 测试1 System Information Discovery
```
systeminfo
reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
```
win10成功复现
###### 测试2 System Information Discovery
```
systemsetup
system_profiler
ls -al /Applications
```
没有成功复现
###### 测试3 List OS Information
```
uname -a >> /tmp/loot.txt
cat /etc/lsb-release >> /tmp/loot.txt
cat /etc/redhat-release >> /tmp/loot.txt
uptime >> /tmp/loot.txt
cat /etc/issue >> /tmp/loot.txt
```
成功复现
###### 测试4 Linux VM Check via Hardware
```
cat /sys/class/dmi/id/bios_version | grep -i amazon
cat /sys/class/dmi/id/product_name | grep -i "Droplet\|HVM\|VirtualBox\|VMware"
cat /sys/class/dmi/id/chassis_vendor | grep -i "Xen\|Bochs\|QEMU"
sudo dmidecode | grep -i "microsoft\|vmware\|virtualbox\|quemu\|domu"
cat /proc/scsi/scsi | grep -i "vmware\|vbox"
cat /proc/ide/hd0/model | grep -i "vmware\|vbox\|qemu\|virtual"
sudo lspci | grep -i "vmware\|virtualbox"
sudo lscpu | grep -i "Xen\|KVM\|Microsoft"
```
成功复现
###### 测试5 Linux VM Check via Kernel Modules
```
sudo lsmod | grep -i "vboxsf\|vboxguest"
sudo lsmod | grep -i "vmw_baloon\|vmxnet"
sudo lsmod | grep -i "xen-vbd\|xen-vnif"
sudo lsmod | grep -i "virtio_pci\|virtio_net"
sudo lsmod | grep -i "hv_vmbus\|hv_blkvsc\|hv_netvsc\|hv_utils\|hv_storvsc"
```
成功复现
###### 测试6 Hostname Discovery (Windows and linux)
```
hostname
```
win10和linux成功复现
###### 测试7 Windows MachineGUID Discovery
```
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid
```
win10成功复现
### T1016 - System Network Configuration Discovery
###### 测试1 System Network Configuration Discovery
```
ipconfig /all
netsh interface show
arp -a
nbtstat -n
net config
```
win10成功复现
###### 测试2 List Windows Firewall Rules
```
netsh advfirewall firewall show rule name=all
```
win10成功复现
###### 测试3 System Network Configuration Discovery
```
arp -a
netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c
ifconfig
```
成功复现
###### 测试4 System Network Configuration Discovery (Trickbot Style)
```
ipconfig /all
net config workstation
net view /all /domain
nltest /domain_trusts
```
win10成功复现
###### 测试5 List Open Egress Ports
就是查看防火墙的出口过滤规则,在powershell中运行
```
1..1024 | % {$test= new-object system.Net.Sockets.TcpClient; $wait = $test.beginConnect("allports.exposed",$_,$null,$null); ($wait.asyncwaithandle.waitone(250,$false)); if($test.Connected){echo "$_ open"}else{echo "$_ closed"}} | select-string " "
```
或者
```
21,22,23,25,80,443,1337 | % {$test= new-object system.Net.Sockets.TcpClient; $wait =$test.beginConnect("allports.exposed",$_,$null,$null); ($wait.asyncwaithandle.waitone(250,$false)); if($test.Connected){echo "$_ open"}else{echo "$_ closed"}} | select-string " "
```
或者
```
80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,3986,13,1029,9,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,19,8031,1041,255,3703,17,808,3689,1031,1071,5901,9102,9000,2105,636,1038,2601,7000 | % {$test= new-object system.Net.Sockets.TcpClient; $wait =$test.beginConnect("allports.exposed",$_,$null,$null); ($wait.asyncwaithandle.waitone(250,$false)); if($test.Connected){echo "$_ open"}else{echo "$_ closed"}} | select-string " "
```
win10成功复现
### T1049 - System Network Connections Discovery
这个就是网络状态的查看
###### 测试1 System Network Connections Discovery
```
netstat
net use
net sessions
```
win10成功复现
###### 测试2 System Network Connections Discovery with PowerShell
```
Get-NetTCPConnection
```
win10成功复现
###### 测试3 System Network Connections Discovery Linux & MacOS
```
netstat
who -a
```
成功复现
### T1033 - System Owner/User Discovery
###### 测试1 System Owner/User Discovery
```
cmd.exe /C whoami
wmic useraccount get /ALL
quser /SERVER:"#{computer_name}"
quser
qwinsta.exe" /server:#{computer_name}
qwinsta.exe
for /F "tokens=1,2" %i in ('qwinsta /server:#{computer_name} ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
@FOR /F %n in (computers.txt) DO @FOR /F "tokens=1,2" %i in ('qwinsta /server:%n ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
```
win10成功复现
###### 测试2 System Owner/User Discovery
```
users
w
who
```
成功复现