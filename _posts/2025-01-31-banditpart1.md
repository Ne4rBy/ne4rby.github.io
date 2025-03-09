---
layout: post
title: OverTheWire Bandit Part 1 WriteUp
date: 2025-01-31
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

Hey there! Today, we’re diving into the **Bandit** game from [OverTheWire](https://overthewire.org/wargames/bandit/). It’s a super cool wargame that’s all about learning the basics of the **Bash** language in a fun and interactive way. The game is made up of 32 levels, each one building on the skills you’ve learned before. Whether you’re just starting with Bash or brushing up on your skills, this is a great way to explore how to navigate, manipulate files, and handle some simple yet tricky challenges. Let’s get started and see how far we can go!

---

## Level 0

At level 0, we just have to use the given credentials in order to log in via **SSH**.

The given credentials are `bandit0:bandit0` and the **SSH** service is hosted at the port `2220`, so we have to make sure that we specify that.

**Command:**  
```bash
ssh -p 2220 bandit0@bandit.labs.overthewire.org
```

**Breakdown:**

- **`ssh`**: Secure Shell, used to remotely connect to another machine over a secure channel.
- **`-p 2220`**: Specifies the port number for the SSH connection. In this case, it's port 2220 instead of the default port 22.
- **`bandit0`**: The username you are logging in with.
- **`@bandit.labs.overthewire.org`**: The hostname of the remote server you're connecting to (in this case, the Bandit game server).

This command connects you to the Bandit game server as the user `bandit0` through port 2220.

Once inside we can just open the only file visible called `readme` and we are rewarded with a password that allow us to get inside of the `bandit1` machine.

```bash
cat readme 
```

---
## Level 1

Once inside, we make a `ls` and we found a file named `-`, that means that if we try opening the file it will crash.

```bash
cat -
```

The command `cat` expects an argument after `-`, as it's typically used for options. To read a file named `-`, you can use the following methods:

**Command:**  
```bash
cat ./-
```

**Breakdown:**

- **`cat`**: Displays the contents of a file.
- **`./-`**: Specifies the file named `-` in the current directory (`./` ensures `-` is treated as a filename rather than an option).

**Command:**  
```bash
cat /home/bandit1/-
```

**Breakdown:**

- **`cat`**: Displays the contents of a file.
- **`/home/bandit1/-`**: The absolute path to the file named `-` in the directory `/home/bandit1`.

---
## Level 2

Once inside we make a `ls` and we can see a file named `spaces in this filename`, as it's says the filename is filled with spaces.

If we try to open the file as it is called.

```bash
cat spaces in this filename
```

The `cat` command will try to open each of the words given as different files, so it will tell us that those files does not exist.

Let's see what methods we can use:

**Command:**  
```bash
cat spaces\ in\ this\ filename
```

**Breakdown:**

- **`cat`**: Displays the contents of a file.
- **`spaces\ in\ this\ filename`**: The file name with spaces, where each space is escaped using a backslash (`\`) to indicate it is part of the filename.

This command reads and displays the content of a file named `spaces in this filename`. Escaping the spaces ensures the shell interprets the filename correctly.

**Command:**
```bash
cat "spaces in this filename"
```

**Breakdown:**

- **`cat`**: Displays the contents of a file.
- **`"spaces in this filename"`**: The file name enclosed in double quotes to handle spaces as part of the filename without needing to escape them.

This command reads and displays the content of a file named `spaces in this filename`, using quotes to treat the entire string as a single filename.

---
## Level 3

Once inside, after making a `ls` we can see a folder named `inhere`, once inside we make another `ls` and there is nothing inside the folder.

```bash
cd inhere
ls
```

In Linux the files that start with a dot (`.file`) are hidden to normal listing, in order to see if there is any hidden file, we can use `ls -la`.

**Command:**  
```bash
ls -la
```


**Breakdown:**

- **`ls`**: Lists the contents of a directory.
- **`-l`**: Displays detailed information about each item (permissions, owner, size, etc.).
- **`-a`**: Includes hidden files (files starting with a `.`) in the listing.

This command shows a detailed list of all files, including hidden ones, in the current directory.

We found a file named `...Hiding-From-You`, so now we can open the file just using `cat`.

```bash
cat ...Hiding-From-You
```

---
## Level 4

**Level Goal**:
- The password for the next level is stored in the only human-readable file in the **inhere** directory.

Once inside we have an `inhere` folder, inside of the folder we can see 10 files, and only one of them is human-readable.

In order to filter for only human-readable files we can use the command `file`

**Command:**  
```bash
file inhere/*
```

**Breakdown:**

- **`file`**: Determines the type of each file (e.g., text, directory, executable).
- **`inhere/*`**: The wildcard `*` matches all files and directories inside the `inhere` directory.

This command checks and displays the file types for all files and directories within the `inhere` directory.

The output will snitch us what file is written in **ASCII**.

**Output:**
```bash
inhere/-file00: data
inhere/-file01: data
inhere/-file02: data
inhere/-file03: data
inhere/-file04: data
inhere/-file05: data
inhere/-file06: data
inhere/-file07: ASCII text
inhere/-file08: data
inhere/-file09: data
```

As you can see the only human-readable file is `-file07`.

---
## Level 5

**Level Goal**:
- The password for the next level is stored in a file somewhere under the **inhere** directory and has all of the following properties:

- human-readable
- 1033 bytes in size
- not executable

For this task we can use the command `find`.

**Command:**  
```bash
find -type f -readable ! -executable -size 1033c
```

**Breakdown:**

- **`find`**: Searches for files and directories in a specified location.
- **`-type f`**: Restricts the search to files only (not directories).
- **`-readable`**: Filters for files that are readable by the user.
- **`! -executable`**: Excludes executable files (`!` negates the condition).
- **`-size 1033c`**: Looks for files that are exactly 1033 bytes in size (`c` stands for bytes).

This command searches inside the `inhere` directory for readable files that are not executable and have a size of exactly 1033 bytes.

After executing, the output show us the file `/inhere/maybehere07/.file2` which is the file we are looking for.

---
## Level 6

**Level Goal**:
- The password for the next level is stored **somewhere on the server** and has all of the following properties:

- owned by user bandit7
- owned by group bandit6
- 33 bytes in size

For this task we can use the command `find` again.

**Command:**  
```bash
find / -user bandit7 -group bandit6 -size 33c 2>/dev/null
```

**Breakdown:**

- **`find`**: Searches for files and directories in the specified location.
- **`/`**: Specifies the root directory to search in (all directories).
- **`-user bandit7`**: Filters for files owned by the user `bandit7`.
- **`-group bandit6`**: Filters for files belonging to the group `bandit6`.
- **`-size 33c`**: Looks for files that are exactly 33 bytes in size (`c` stands for bytes).
- **`2>/dev/null`**: Redirects any error messages (stderr) to `/dev/null` to suppress them from being displayed.

This command searches the entire file system for files that are owned by `bandit7`, belong to the group `bandit6`, and are exactly 33 bytes in size, while suppressing error messages.

After executing, the output show us the file `/var/lib/dpkg/info/bandit7.password` which is the file we are looking for.

---
## Level 7

**Level Goal**:
- The password for the next level is stored in the file **data.txt** next to the word **millionth**.

For this task we can use the command `cat` combined with `grep` and then using `awk`.

**Command:**  
```bash
cat data.txt | grep "millionth" | awk '{print $2}'
```

**Breakdown:**

- **`cat data.txt`**: Displays the content of `data.txt`.
- **`|`**: Pipes the output of `cat` to the next command.
- **`grep "millionth"`**: Searches for the line containing the word `"millionth"`.
- **`|`**: Pipes the filtered output to `awk`.
- **`awk '{print $2}'`**: Prints the second field (word) from the matching line, assuming fields are space-separated.

This command finds the line containing `"millionth"` in `data.txt` and extracts its second word.

After executing the output is the password of the the user `bandit8`.

---
## Level 8

**Level Goal**:
- The password for the next level is stored in the file data.txt and is the only line of text that occurs only once.

For this task we can use the command `cat` combined with `sort` and combined with `uniq`

**Command:**  
```bash
cat data.txt | sort | uniq -u
```

**Breakdown:**

- **`cat data.txt`**: Displays the content of `data.txt`.
- **`|`**: Pipes the output to the next command.
- **`sort`**: Sorts the lines in `data.txt` (needed for `uniq` to work correctly).
- **`|`**: Pipes the sorted output to `uniq`.
- **`uniq -u`**: Filters and displays only unique lines that appear exactly once (removes duplicates).

This command extracts and displays lines in `data.txt` that occur only once, after sorting them.

After executing the output is the password of the the user `bandit9`.

---
## Level 9

**Level Goal**:
- The password for the next level is stored in the file **data.txt** in one of the few human-readable strings, preceded by several ‘=’ characters.

For this task we can use the command `string` combined with `grep` then `tail` and finally `awk`.

**Command:**  
```bash
strings data.txt | grep "=====" | tail -n 1 | awk 'NF{print $NF}'
```

**Breakdown:**

- **`strings data.txt`**: Extracts readable text from `data.txt` (useful for binary or non-text files).
- **`|`**: Pipes the output to the next command.
- **`grep "====="`**: Searches for lines containing `"====="`.
- **`|`**: Pipes the filtered output to `tail`.
- **`tail -n 1`**: Selects the last matching line.
- **`|`**: Pipes the selected line to `awk`.
- **`awk 'NF{print $NF}'`**: Prints the last field (word) of the line (`NF` represents the number of fields, and `$NF` is the last field).

This command extracts the last readable line in `data.txt` that contains `"====="` and prints its last word.

After executing the output is the password of the the user `bandit10`.

---
## Level 10

**Level Goal**:
- The password for the next level is stored in the file **data.txt**, which contains base64 encoded data.

For this task we can use the command `base64` combined with `awk`.

**Command:**  
```bash
base64 -d data.txt | awk 'NF{print $NF}'
```

**Breakdown:**

- **`base64 -d data.txt`**: Decodes the Base64-encoded content of `data.txt`.
- **`|`**: Pipes the decoded output to `awk`.
- **`awk 'NF{print $NF}'`**: Prints the last field (word) of each non-empty line (`NF` represents the number of fields, and `$NF` is the last field).

This command decodes `data.txt` from Base64 and extracts the last word from each non-empty line.

After executing the output is the password of the the user `bandit11`.

---
## Level 11

**Level Goal**:
- The password for the next level is stored in the file **data.txt**, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions.

For this task we can use the command `cat` combined with `tr` and `awk`. 

**Command:**  
`cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m' | awk 'NF{print $NF}'`

**Breakdown:**

- **`cat data.txt`**: Displays the content of `data.txt`.
- **`|`**: Pipes the output to the next command.
- **`tr 'A-Za-z' 'N-ZA-Mn-za-m'`**: Applies the **ROT13 cipher**, a simple letter substitution technique that shifts each letter by 13 positions in the alphabet:
    - **`A-M`** maps to **`N-Z`**, and **`N-Z`** maps to **`A-M`** (for uppercase letters).
    - **`a-m`** maps to **`n-z`**, and **`n-z`** maps to **`a-m`** (for lowercase letters).
    - This transformation effectively "mirrors" the alphabet at the 13th letter, making ROT13 its own inverse (applying it twice restores the original text).
- **`|`**: Pipes the decoded output to `awk`.
- **`awk 'NF{print $NF}'`**: Extracts and prints the last word (`$NF`) of each non-empty line (`NF` ensures empty lines are ignored).

This command deciphers `data.txt` using **ROT13** and extracts the last word from each non-empty line.

After executing the output is the password of the the user `bandit12`.

---
## Level 12

**Level Goal**:
- The password for the next level is stored in the file **data.txt**, which is a hexdump of a file that has been repeatedly compressed. 

For this task we are going to create our first **bash script**.

But first of all, let's see what we are facing, once logged we see the `data.txt` containing hexadecimal content, so let's reverse the content to it's original content.

```bash
xxd -r data.txt > data
```

After getting the original file we can now see if this file is a compressed file.

```bash
file data

data: gzip compressed data, was "data2.bin", last modified: Thu Sep 19 07:08:15 2024, max compression, from Unix, original size modulo 2^32 574
```

It is a `gzip` file, so let's name it correctly.

```bash
mv data data.gzip
```

*I do recommend that you transfer the file to your own machine*

We know the file `data.gzip` has been repeatedly compressed, so we could just keep decompressing file per file until we get the original file and that's fine, but we would learn nothing, so let's make a script automatizing the process.

So i have created this script:

```bash
#!/bin/bash

name_compressed=$(7z l data.gzip | tail -n 3 | head -n 1 | awk 'NF{print $NF}')

7z x data.gzip > /dev/null 2>&1

while true; do
	7z l $name_compressed > /dev/null 2>&1
	
	if [ "$(echo $?)" == "0" ]; then
		decompressed_next=$(7z l $name_compressed | tail -n 3 | head -n 1 | awk 'NF{print $NF}')
		7z x $name_compressed > /dev/null 2>&1 && name_compressed=$decompressed_next
	else 
		echo "[+] Original filename: $decompressed_next"
		cat $decompressed_next
		exit 1
	fi	

done
```

I would like to explain by myself, but it's a bit hard for me to explain via writing, at one point i'll start making videos for easier explaining, but i have no time at the moment.

So i just asked ChatGPT to explain it:

### Explanation of the Script

This Bash script recursively extracts nested 7z-compressed files until it finds a non-archive file, which it then prints to the terminal.

---

### Breakdown

#### 1. Extract the First File Name from the Given Archive

```bash
name_compressed=$(7z l $1 | tail -n 3 | head -n 1 | awk 'NF{print $NF}')
```

- **`7z l $1`** → Lists the contents of the provided archive (`$1` is the input file).
- **`tail -n 3 | head -n 1`** → Extracts the name of the file inside the archive (assumes only one file per archive).
- **`awk 'NF{print $NF}'`** → Extracts the last field (filename) from the line.

At this point, `name_compressed` holds the name of the extracted file inside the archive.

---

#### 2. Extract the First Archive

```bash
7z x $1 > /dev/null 2>&1
```

- **`7z x $1`** → Extracts the input archive.
- **`> /dev/null 2>&1`** → Suppresses both standard output and error messages.

Now, the first extracted file is in the same directory.

---

#### 3. Begin the Loop to Handle Nested Archives

```bash
while true; do
	7z l $name_compressed > /dev/null 2>&1
```

- **The script enters an infinite loop (`while true`).**
- **`7z l $name_compressed`** → Checks if the extracted file is another archive.
- **`> /dev/null 2>&1`** → Suppresses output.

If the file is another archive, the script continues extracting. If it's not, the script prints its contents and exits.

---

#### 4. Check If the File is a 7z Archive

```bash
if [ "$(echo $?)" == "0" ]; then
```

- **`$?`** → Holds the exit status of the last command (0 means success, meaning it's an archive).
- **If the file is an archive, the script continues extracting.**

If the file is NOT an archive, it means we reached the final (non-compressed) file.

---

#### 5. Extract the Next Archive

```bash
decompressed_next=$(7z l $name_compressed | tail -n 3 | head -n 1 | awk 'NF{print $NF}')
7z x $name_compressed > /dev/null 2>&1 && name_compressed=$decompressed_next
```

- **`decompressed_next`** → Gets the name of the file inside the current archive.
- **`7z x $name_compressed`** → Extracts it.
- **`name_compressed=$decompressed_next`** → Updates `name_compressed` to the new extracted file, so the loop continues.

The process repeats until a non-archive file is found.

---

#### 6. If It's Not an Archive, Print the Final File

```bash
else 
	echo "[+] Original filename: $decompressed_next"
	cat $decompressed_next
	exit 1
fi	
```

- **If the file is NOT a 7z archive, it prints the original filename and displays its content using `cat`.**
- **`exit 1`** → Terminates the script.

---

### Summary of the Script

1. Extracts the first file from the given archive.
2. If it's another 7z file, it extracts it and continues the process.
3. If it's not an archive, it prints the filename and displays its contents.
4. The process continues recursively until the original (uncompressed) file is found.

This script is useful for handling multi-layered 7z archives that contain other compressed files inside them.

That's it, after executing we will have all the compressed files unzipped and the `bandit13` user's password on screen.

---
## Level 13

**Level Goal**:
- The password for the next level is stored in **/etc/bandit_pass/bandit14 and can only be read by user bandit14**. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. 

For this task we are going to create our first `ssh`.

### What is a Private Key in SSH?

A **private key** is part of a cryptographic key pair used in **public-key authentication** for SSH connections. This key pair consists of:

1. **Public Key** → Stored on the remote server in `~/.ssh/authorized_keys`.
2. **Private Key** → Kept securely on the client machine and never shared.

When connecting to a server using SSH, the client proves its identity by using the private key, without ever sending it over the network. The server verifies this by checking if the corresponding **public key** exists in its authorized keys list.

Using a private key for authentication enhances security compared to passwords, as it prevents brute-force attacks and eliminates the need to manually enter a password for each login.

**Command:**  
```bash
ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
```

**Breakdown:**

- **`ssh`** → Initiates an SSH connection to a remote host.
- **`-i sshkey.private`** → Specifies a private key file (`sshkey.private`) for authentication instead of a password.
- **`bandit14@bandit.labs.overthewire.org`** → Connects as user `bandit14` to the server `bandit.labs.overthewire.org`.
- **`-p 2220`** → Uses port `2220` instead of the default SSH port (`22`).

This command establishes an SSH connection to the `bandit14` user on `bandit.labs.overthewire.org` using a specific private key for authentication and a non-default port.

Once logged as `bandit14`, we can open the file at `/etc/bandit_pass/bandit14`.

```bash
cat /etc/bandit_pass/bandit14
```

The password is now at the screen.

----
## Level 14

**Level Goal**:
- The password for the next level can be retrieved by submitting the password of the current level to **port 30000 on localhost**.

For this task we are going to create our first `nc`.

**Command:**

```bash
nc -nv 127.0.0.1 30000
```

**Breakdown:**

- **`nc`** → Runs `netcat`, a tool for reading and writing data over network connections.
- **`-n`** → Disables DNS resolution, preventing `netcat` from attempting to resolve hostnames.
- **`-v`** → Enables verbose mode, providing additional details about the connection attempt.
- **`127.0.0.1`** → The localhost IP address, meaning the connection is made to the same machine.
- **`30000`** → The target port number to connect to.

This command attempts to establish a **TCP connection** to **port 30000** on **localhost** (`127.0.0.1`). If a service is listening on that port, `netcat` will connect and allow interaction with it.

Then we just have to paste the password of the user `bandit14` and we will be prompted with the password of the user `bandit15`.

---
## Level 15

**Level Goal**
- The password for the next level can be retrieved by submitting the password of the current level to **port 30001 on localhost** using SSL/TLS encryption.

**Command:**

```bash
openssl s_client -connect 127.0.0.1:30001
```

**Breakdown:**

- **`openssl`** → A toolkit for SSL/TLS encryption, commonly used for testing secure connections.
- **`s_client`** → Initiates an SSL/TLS client connection to a specified server and port.
- **`-connect 127.0.0.1:30001`** → Specifies the target IP (`127.0.0.1`, which is localhost) and port (`30001`) to connect to using SSL/TLS.

This command attempts to establish a **secure (TLS/SSL) connection** to **port 30001** on **localhost**. If a service is listening on that port with TLS/SSL enabled, `openssl s_client` will negotiate a secure connection and display certificate details, session information, and allow manual interaction with the encrypted service.

Then we just have to paste the password of the user `bandit15` and we will be prompted with the password of the user `bandit16`.

---

## Level 16

**Level Goal**:
- The credentials for the next level can be retrieved by submitting the password of the current level to **a port on localhost in the range 31000 to 32000**. First find out which of these ports have a server listening on them. Then find out which of those speak SSL/TLS and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

For this task i will automate the port discovery section with a **bash script** and then manually check the ports with `openssl`.

I made this tiny script to see which open ports are in the range of `31000-32000`.

```bash
#!/bin/bash

for i in $(seq 31000 32000); do
	(echo > /dev/tcp/127.0.0.1/$i) > /dev/null 2>&1 && echo "[+] Port $i - OPEN"
        
done
```

Again, ChatGPT will explain you the script in detail:
### Explanation of the Script

This Bash script checks a range of ports (from 31000 to 32000) on the local machine (`127.0.0.1`) and prints out which ports are open.

---
### Breakdown

#### 1. Start the Loop for Port Scanning

```bash
for i in $(seq 31000 32000);
```

- **`seq 31000 32000`** → Generates a sequence of numbers from 31000 to 32000.
- **`for i in $(seq 31000 32000)`** → Starts a loop that iterates over each port in the sequence.

At this point, the variable `i` holds the current port number.

---

#### 2. Attempt to Connect to Each Port

```bash
(echo > /dev/tcp/127.0.0.1/$i) > /dev/null 2>&1
```

- **`/dev/tcp/127.0.0.1/$i`** → Attempts to establish a TCP connection to `127.0.0.1` on port `$i`.
    - If the port is **open**, the connection is successful.
    - If the port is **closed**, the connection fails.
- **`echo >`** → Sends an empty message to the port (just a simple connection attempt).
- **`> /dev/null 2>&1`** → Suppresses both standard output and error output, meaning no messages are displayed during the connection attempt.

---

#### 3. Check if the Port Is Open

```bash
&& echo "[+] Port $i - OPEN"
```

- **`&&`** → If the previous command (the connection attempt) was successful (i.e., the port is open), it proceeds to the next part.
- **`echo "[+] Port $i - OPEN"`** → Prints the message indicating that port `$i` is open.

---

### Summary of the Script

1. The script loops through a sequence of port numbers from 31000 to 32000.
2. For each port, it attempts to establish a TCP connection to `127.0.0.1`.
3. If the port is open, it prints a message indicating that the port is open.
4. The process continues for all ports in the specified range.

This script is useful for quickly checking which ports in a specific range are open on the local machine.

So, in our case we have found the following ports:

```bash
[+] Port 31046 - OPEN
[+] Port 31518 - OPEN
[+] Port 31691 - OPEN
[+] Port 31790 - OPEN
[+] Port 31960 - OPEN
```

We can now use `openssl` in order to check which of the ports give us the password of the next level when we submit the current password.

```bash
openssl s_client -connect 127.0.0.1:31XXX
```

Just try repeatedly with each of the ports until you get the password right.

*Note -> In case the password you have to submit starts with `K` add the `-quiet` flag to the command so you don't get the response `KEYUPDATE` and get the privete key instead*

Once you get the right port you will be prompted with the private key of `bandit17` so we just have to copy it and add it to a file named `id_rsa` with the perm `600`.

```bash
vim id_rsa
chmod 600 id_rsa
ssh -i id_rsa -p 2220 bandit17@bandit.labs.overthewire.org
```

---
## Level 17

**Level Goal**:
- There are 2 files in the homedirectory: **passwords.old and passwords.new**. The password for the next level is in **passwords.new** and is the only line that has been changed between **passwords.old and passwords.new**

For this task we can use the command `diff`.

**Command:**

```bash
diff passwords.old passwords.new
```

**Breakdown:**

- **`diff`** → Compares two files line by line and displays the differences between them.
- **`passwords.old`** → The first file to compare (in this case, the older version of the password list).
- **`passwords.new`** → The second file to compare (in this case, the updated version of the password list).

This command compares the contents of `passwords.old` and `passwords.new` and outputs the differences. It helps identify what has changed between the two files, such as added, removed, or modified lines.

The password in the bottom is the password of the user `bandit18`.

---
## Completion of Bandit Game - Levels 1 to 17

That concludes part 1 of the Bandit game, where I’ve completed levels up to 17. It’s been an engaging experience so far, and there's still more to uncover. I’ll be continuing with part 2 to tackle the remaining challenges. Stay tuned for the next post!