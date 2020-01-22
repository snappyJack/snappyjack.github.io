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

###### 测试1 Windows - Discover domain trusts with dsquery
```
dsquery * -filter "(objectClass=trustedDomain)" -attr *
```
没有dsquery命令
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
