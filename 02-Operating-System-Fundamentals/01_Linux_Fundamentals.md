
# 01 - Linux Fundamentals

## Introduction — quick student notes
- Linux: free, open-source OS created by Linus Torvalds (1991). Used on servers, desktops, mobiles and supercomputers.
- Strengths: stability, security, flexibility. Many distributions package the Linux kernel with different software sets.

## Linux philosophy (short)
- Freedom: control, modify, redistribute software.
- Collaboration: many developers contribute worldwide.
- Transparency: source code is open and auditable.

## How Linux works — essentials
- Kernel: core component that manages CPU, memory, and devices; translates application requests into hardware actions.
- Userspace: tools, libraries, GUIs and applications that run on top of the kernel.
- Linux supports multi-user and multitasking environments (good for servers).
- Filesystem is hierarchical, starting at root `/`.

## Linux architecture (layers)
- Hardware layer: CPU, RAM, disks, peripherals.
- Kernel layer: resource management (scheduling, memory, I/O).
- Shell layer: user interface (CLI or graphical shell) that talks to the kernel.
- System utility layer: tools and daemons that perform system tasks.

## Distributions (distros) — short guide
- A distro = kernel + libraries + apps + package manager + bootloader (+ GUI optional).
- Popular examples and focus:
	- Ubuntu: beginner-friendly, desktop & server.
	- Fedora: cutting-edge, developers.
	- CentOS: stable, enterprise servers (RHEL-compatible).
	- Debian: stable, large repo.
	- Arch: experienced users, rolling-release, highly customizable.
	- Kali: security / pentesting tools preinstalled.
- Choose distro based on purpose (desktop, server, support, hardware, packages).

## Shell & Terminal (student-level)
- Shell: command-language interpreter (Bash, Zsh, Csh, Ksh, Fish).
- Terminal: application that runs a shell.
- CLI is powerful for automation (shell scripts).

Common shells:
- Bash: default on many systems, strong scripting support.
- Zsh: advanced completion, themes (Oh My Zsh).
- Fish: user-friendly features out of the box.

## Basic navigation & filesystem
- Root directory: `/` is the base.
- Important dirs: `/bin`, `/sbin`, `/etc`, `/home`, `/var`, `/usr`.
- Show current dir: `pwd`
- List files: `ls` (details: `ls -l`, include hidden: `ls -a`, combined: `ls -la`).
- Hidden files start with `.` (e.g. `.bashrc`).
- Change dir: `cd /path` (back to previous: `cd -`).
- Tab completion speeds navigation.

## File & directory operations (commands)
- Create file: `touch filename`
- Make directory: `mkdir dirname`
- Copy file: `cp source dest` (recursive: `cp -r dir target`)
- Move / rename: `mv source dest`
- Remove file: `rm file` (remove directory recursively: `rm -r dir`)

## Finding files
- `find [path] [criteria]` — powerful, criteria examples: `-name`, `-type`, `-size`, `-mtime`.
	- e.g. `find / -name "notes.txt"`
- `locate name` — fast, uses `updatedb` index (may be stale).
- `which command` — shows path to executable (useful to know which version runs).

## Text editing & viewing
- `nano filename` — simple terminal editor (save: Ctrl+O, exit: Ctrl+X, search: Ctrl+W).
- `cat file` — print file contents.
- `head -n N file` — first N lines.
- `tail -n N file` — last N lines (good for logs; `tail -f` to follow).

## Filters and text tools (quick)
- `sort file` — sort lines.
- `uniq` — remove consecutive duplicate lines (commonly used after `sort`).
- `grep 'pattern' file` — search for pattern in file(s).
- `wc -l file` — count lines (`-w` words, `-c` bytes).
- `sed 's/old/new/' file` — stream editor for substitutions (prints changes unless redirected).
- `awk '{print $1}' file` — field-based processing (good for columnar data).

## Package management (APT — Debian/Ubuntu)
- Update package lists: `sudo apt update`
- Search packages: `sudo apt search name` or `sudo apt search --names-only name`
- Install: `sudo apt install package`
- Upgrade installed packages: `sudo apt upgrade`
- Dist-upgrade (more aggressive): `sudo apt dist-upgrade`
- Remove package: `sudo apt remove package`
- Purge package + config: `sudo apt purge package`

## Users & groups (basics)
- User attributes: username, UID, GID, home dir, shell, password.
- Create user: `useradd -u UID -d /home/name -s /bin/bash name`
- Check user IDs/groups: `id username` and `/etc/passwd` contents.
- Change password: `sudo passwd username`
- Delete user: `sudo userdel username`

Group management:
- Create group: `sudo groupadd groupname`
- Add user to group: `sudo usermod -aG groupname username`
- Delete group: `sudo groupdel groupname`

## File permissions (concise)
- Permission string (example): `rwxr--r--` → user | group | others.
- `r` read, `w` write, `x` execute; `-` means no permission.
- Change permissions: symbolic `chmod ugo+rwx file` or `chmod o+w file` (add write for others).
- `ls -l` shows owner & group and permission bits.

## Processes (management)
- Process = running program (has PID).
- Foreground: locks terminal until done. Background: append `&` to run in background.
- `jobs` — show background jobs in current shell.
- `fg %1` — bring job 1 to foreground.
- `ps` / `ps -f` — list processes (system-wide view).
- Kill process: `kill PID` (force: `kill -9 PID`).

## Network basics & tools (Debian-derived notes)
- `ifconfig` — list/inspect/configure network interfaces (traditional tool).
	- `ifconfig` or `ifconfig -a` show interfaces.
	- Bring interface up: `ifconfig eth0 up`; down: `ifconfig eth0 down`.
	- Assign IP: `ifconfig eth0 172.20.1.110`
	- Set netmask: `ifconfig eth0 netmask 255.255.255.0`
	- Promiscuous mode: `ifconfig eth0 promisc` (enable) / `ifconfig eth0 -promisc` (disable).
	- Change MAC: `ifconfig eth0 hw ether AA:BB:CC:DD:EE:FF`.
- DNS config: `/etc/resolv.conf` (edit with `nano`), e.g., `nameserver 1.1.1.1`.

## SSH basics
- Install server (Debian): `sudo apt-get update && sudo apt-get install openssh-server`
- Start service: `sudo systemctl start ssh` and enable on boot: `sudo systemctl enable ssh`.
- Connect: `ssh user@ip_address` (e.g., `ssh root@192.168.1.100`).
- Key-based auth: `ssh-keygen` then `ssh-copy-id user@ip_address`.
- Config: `/etc/ssh/sshd_config` (e.g., change `Port 2222`); restart with `sudo systemctl restart ssh`.

---

