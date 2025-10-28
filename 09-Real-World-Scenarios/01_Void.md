# 01 - Void (Lab)


According to our security analysts' reports, our critical systems have been subjected to scans from a suspicious IP address for some time. Your mission is to identify the owner of this IP address and the associated server, and to uncover what the attackers are doing. Good luck!

Questions Walkthrough:

1. What is the email address and password for the attacker's GitHub account?

First lets perform a nmap scan against the target IP address to identify open ports and services.

```
nmap -sSVC 172.20.58.19 
```
```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 2e:c4:78:c6:8e:54:93:96:80:02:e7:fd:18:26:a1:4e (RSA)
|   256 0f:92:e6:7d:b7:58:9d:12:e2:2d:df:54:c6:23:0a:41 (ECDSA)
|_  256 b3:94:dd:c5:08:7c:22:3b:14:c0:01:e0:74:29:62:8c (ED25519)
10000/tcp open  http    MiniServ 1.890 (Webmin httpd)
Lets look for any suspicious files on the system.
````markdown
# 01 - Void (Lab)


According to our security analysts' reports, our critical systems have been subjected to scans from a suspicious IP address for some time. Your mission is to identify the owner of this IP address and the associated server, and to uncover what the attackers are doing. Good luck!

Questions Walkthrough:

1. What is the email address and password for the attacker's GitHub account?

First lets perform a nmap scan against the target IP address to identify open ports and services.

```
nmap -sSVC 172.20.58.19 
```
```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 2e:c4:78:c6:8e:54:93:96:80:02:e7:fd:18:26:a1:4e (RSA)
|   256 0f:92:e6:7d:b7:58:9d:12:e2:2d:df:54:c6:23:0a:41 (ECDSA)
|_  256 b3:94:dd:c5:08:7c:22:3b:14:c0:01:e0:74:29:62:8c (ED25519)
10000/tcp open  http    MiniServ 1.890 (Webmin httpd)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Login to Webmin
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
It seems that the target is running a Webmin service on port 10000, which is a web-based interface for system administration. We should investigate this service further to find any vulnerabilities or misconfigurations that could be exploited.

Lets look in msfconsole for any available exploits for Webmin.

```
msfconsole
search webmin 1.8
```

![](../Assets/Pasted%20image%2020251028134800.png)

Great we found this exploit for Webmin 1.890. Lets use it.


![](../Assets/Pasted%20image%2020251028135041.png)


Great after running it we earned a root shell on the target machine. Lets try to awnser the first question.
```
find / -name ".git" -type d 2>/dev/null
```

![](../Assets/Pasted%20image%2020251028135307.png)

Here on the .git we found a help.txt file. Lets read it.
```
cat help.txt
```

![](../Assets/Pasted%20image%2020251028135608.png)

We found the email and password for the attackers github account.
Answer: timmycoat@anonymmail.hv:wTWQzVeTD3vm

Question 2: What is the MD5 hash value of the malware used by the attacker?

Lets look for any suspicious files on the system.
```
find / -iname "*malware*" -type f 2>/dev/null
```

![](../Assets/Pasted%20image%2020251028135944.png)

Here we found `/root/phishing_malware.zip`
Lets get it and try to unzip it first.```
```
python3 -m http.server 8080
```
On our local machine we run a simple http server to transfer the file.
```
wget http://172.20.58.19:8080/root/phishing_malware.zip
unzip phishing_malware.zip
```

It has a password lets unzip it using zip2john to crack it.
```
zip2john phishing_malware.zip > ziphash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt
```
Bingo !! We got the password.

![](../Assets/Pasted%20image%2020251028141035.png)

Lets unzip it now and get the md5sum of the file.
```
unzip phishing_malware.zip
md5sum phishing_malware.pdf
```

![](../Assets/Pasted%20image%2020251028141103.png)

Awnser: b82f8ba530a975e9f2acefe675fbffce


Question 3: What is the domain name that the attacker scanned with the SQL Injection scanning tool?

Lets look for any sqlmap logs on the system.
```find / -iname "*sqlmap*" -type d 2>/dev/null
```
Here we found `/root/.local/share/sqlmap/output/`

![](../Assets/Pasted%20image%2020251028141341.png)

On the following folder we found a target.txt

![](../Assets/Pasted%20image%2020251028141424.png)

Answer: albireobank.hv

Question 4: What is the e-mail address of the victim in the “Stealer Log” data on the server?

Lets look for any stealer logs on the system.
`ls -la /home/void/Downloads/best-log/`

![](../Assets/Pasted%20image%2020251028141644.png)

Here we have a Password.txt lets read it.
```
cat /home/void/Downloads/best-log/Password.txt
```

![](../Assets/Pasted%20image%2020251028141807.png)

Here we have the victim
Answer: christopher1d@zeromail.hv

Question 5: Which IP address did the attacker scan for ports and services?

Lets look for any nmap scans on the system logs.
```
ls -la /nmap/
```
Here we found `scan_results.xml`

![](../Assets/Pasted%20image%2020251028142104.png)

Answer: 45.76.59.241
```