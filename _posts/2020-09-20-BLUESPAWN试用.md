---
layout: post
title: bluespawn工具试用
excerpt: "工具试用"
categories: [Redteam]
comments: true
---


### BLUESPAWN

项目地址 `https://github.com/ION28/BLUESPAWN`

对主机安全配置的审计
```
C:\Users\john\Desktop>BLUESPAWN-client-x64.exe --mitigate --action=audit


________ ______ _____  ____________________________ _______ ___       _______   __
___  __ )___  / __  / / /___  ____/__  ___/___  __ \___    |__ |     / /___  | / /
__  __  |__  /  _  / / / __  __/   _____ \ __  /_/ /__  /| |__ | /| / / __   |/ /
_  /_/ / _  /___/ /_/ /  _  /___   ____/ / _  ____/ _  ___ |__ |/ |/ /  _  /|  /
/_____/  /_____/\____/   /_____/   /____/  /_/      /_/  |_|____/|__/   /_/ |_/



[*][LOW] Auditing Mitigations
[INFO] Checking for presence of M1025 - Privileged Process Integrity
[WARNING] M1025 - Privileged Process Integrity is NOT configured.
[*][LOW] M1025 - Privileged Process Integrity is NOT configured.
[INFO] Checking for presence of M1028-WFW - Windows Firewall must be enabled with no exceptions
[WARNING] M1028-WFW - Windows Firewall must be enabled with no exceptions is NOT configured.
[*][LOW] M1028-WFW - Windows Firewall must be enabled with no exceptions is NOT configured.
[INFO] Checking for presence of M1035-RDP - Limit Access to Resource over Network
[INFO] M1035-RDP - Limit Access to Resource over Network is enabled.
[*][LOW] M1035-RDP - Limit Access to Resource over Network is enabled.
[INFO] Checking for presence of M1042-LLMNR - Link-Local Multicast Name Resolution (LLMNR) should be disabled
[WARNING] M1042-LLMNR - Link-Local Multicast Name Resolution (LLMNR) should be disabled is NOT configured.
[*][LOW] M1042-LLMNR - Link-Local Multicast Name Resolution (LLMNR) should be disabled is NOT configured.
[INFO] Checking for presence of M1042-NBT - NetBIOS Name Service (NBT-NS) should be disabled
[WARNING] M1042-NBT - NetBIOS Name Service (NBT-NS) should be disabled is NOT configured.
[*][LOW] M1042-NBT - NetBIOS Name Service (NBT-NS) should be disabled is NOT configured.
[INFO] Checking for presence of M1042-WSH - Windows Script Host (WSH) should be disabled
[WARNING] M1042-WSH - Windows Script Host (WSH) should be disabled is NOT configured.
[*][LOW] M1042-WSH - Windows Script Host (WSH) should be disabled is NOT configured.
...
```

对主机行为的监控
```
C:\Users\john\Desktop>BLUESPAWN-client-x64.exe  --monitor -a Cursory --log=console,xml


 ____  ____  ____  ____  ____  ____  ____  ____  ____
||B ||||L ||||U ||||E ||||S ||||P ||||A ||||W ||||N ||
||__||||__||||__||||__||||__||||__||||__||||__||||__||
|/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\||/__\|




[*][LOW] Monitoring the system
[*][LOW] Setting up monitoring for T1036 - Masquerading
[*][LOW] Setting up monitoring for T1037 - Boot or Logon Initialization Scripts
[*][LOW] Setting up monitoring for T1053 - Scheduled Task/Job
[*][LOW] Setting up monitoring for T1055 - Process Injection
[*][LOW] Setting up monitoring for T1068 - Exploitation for Privilege Escalation
[*][LOW] Setting up monitoring for T1070 - Indicator Removal on Host
[*][LOW] Setting up monitoring for T1136 - Create Account
[*][LOW] Setting up monitoring for T1484 - Group Policy Modification
[*][LOW] Setting up monitoring for T1505 - Server Software Component
[*][LOW] Setting up monitoring for T1543 - Create or Modify System Process
[ERROR] Failed to subscribe to changes to  (Error 6)
```
同时运行测试脚本
```
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "C:\temp\evil.exe"
```
此时看到已经监控到了该行为
```
[INFO] Beginning hunt for T1546 - Event Triggered Execution
[INFO] Skipping T1546 - Event Triggered Execution Subtechnique 012: Image File Execution Options Injection subsection IFEO_HIJACK; rerun BLUESPAWN at Normal to run this.
[INFO] Beginning hunt for T1546 - Event Triggered Execution
[INFO] Skipping T1546 - Event Triggered Execution Subtechnique 012: Image File Execution Options Injection subsection IFEO_HIJACK; rerun BLUESPAWN at Normal to run this.
```

hunt模式
```
C:\Users\john\Desktop>BLUESPAWN-client-x64.exe --hunt -a Cursory --log=console,xml

...
...

[DETECTION] Detection ID: 1
        Detection Recorded at 2020-09-20 08:11:28.405Z
        Detected by: T1546 - Event Triggered Execution Subtechnique 008: Accessibility Features
        Detection Type: Registry
        Detection Certainty: 1
        Detection Data:
                Key Path: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\atbroker.exe
                Key Value Data: C:\windows\system32\calc.exe
                Key Value Name: Debugger
                Registry Entry Type: Command
[INFO] Skipping T1546 - Event Triggered Execution Subtechnique 015: Component Object Model Hijacking subsection COM_HIJACK; rerun BLUESPAWN at Intensive to run this.
[INFO] Detections with IDs 3 and 4 now are associated with strength 1
```
此时已经发现了一些有害的操作

