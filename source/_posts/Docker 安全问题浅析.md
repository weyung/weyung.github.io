---
title: Docker 安全问题浅析
date: 2025-04-03 17:22:00
tags: [Web, 渗透]
categories: 渗透
---

学习一下常用的逃逸手法，以及如何设计一个安全的方案。
<!--more-->

## 前言

自从听说 Docker 给 root 会导致安全风险，潜意识就觉得 Docker 里的 root 和宿主机的 root 是一回事，但是被问到的时候面试官又说特权模式才会有风险，特权用户无所吊谓，不然 NameSpace 干嘛的呢？

## 前置知识

### UID & GID

我们知道，Linux 通过 UID 来标识用户，且 UID 是唯一的，UID 为 0 的用户是 root 用户。
可以通过 `/etc/passwd` 文件来查看用户信息，格式如下：

```bash
kali@cverc:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:113:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:116::/run/uuidd:/usr/sbin/nologin
systemd-oom:x:108:117:systemd Userspace OOM Killer,,,:/run/systemd:/usr/sbin/nologin
tcpdump:x:109:118::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
avahi:x:114:121:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:115:122:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
rtkit:x:116:123:RealtimeKit,,,:/proc:/usr/sbin/nologin
whoopsie:x:117:124::/nonexistent:/bin/false
sssd:x:118:125:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
speech-dispatcher:x:119:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
fwupd-refresh:x:120:126:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
nm-openvpn:x:121:127:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
saned:x:122:129::/var/lib/saned:/usr/sbin/nologin
colord:x:123:130:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:124:131::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:125:132:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:126:65534::/run/gnome-initial-setup/:/bin/false
hplip:x:127:7:HPLIP system user,,,:/run/hplip:/bin/false
gdm:x:128:134:Gnome Display Manager:/var/lib/gdm3:/bin/false
kali:x:1000:1000:kali,,,:/home/kali:/bin/bash
sshd:x:129:65534::/run/sshd:/usr/sbin/nologin
ftp:x:130:138:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

可以看到，用户分为如下几类：

- Root 用户：UID 为 0，拥有最高权限。
- 系统用户：UID 通常为 1-999（不同系统范围可能不同），用于运行系统服务（如 www-data、mysql）。
- 普通用户：UID 从 1000 或 10000 开始分配（依系统而定），供普通用户使用（如上面的 kali）。

文件/进程的访问权限都是基于 UID 进行判断的，进程在运行时会继承启动用户的 UID，决定其资源访问范围。
当然有特殊情况——那就是 setuid。
进程的 UID 其实还细分为 RUID（Real UID）和 EUID（Effective UID），前者是进程实际所有者的 UID，后者则决定进程权限，这就是 SUID（Set User ID） 机制。
刚好发现 WSL 的 `ping` 坏了（虽然我也不确实是不是一直都这样），具体表现就是没权限，详细如下：

```bash
$ ping baidu.com
ping: socktype: SOCK_RAW
ping: socket: Operation not permitted
ping: => missing cap_net_raw+p capability or setuid?
```

前几次都忍了，加个 `sudo` 也能用，但是今天既然都写到这就干脆修一下

```bash
$ ls -l /usr/bin/ping
-rwxr-xr-x 1 root root 156136 Sep 25  2024 /usr/bin/ping
```

执行 `sudo chmod u+s /usr/bin/ping`，再看：

```bash
-rwsr-xr-x 1 root root 156136 Sep 25  2024 /usr/bin/ping
```

可以看到多了个 `s`，即 SUID 的标志位，运行时会将 EUID 设置为文件所有者的 UID（即 root），就可以畅快地 ping 了。

值得一提的是，对于脚本文件（如 `.sh`），SUID 是无效的，只有二进制文件才有效，这也是 Linux 的安全设计，之前做渗透的时候踩过坑。

做渗透测试的时候也可以用 `find / -perm -4000` 命令查找 SUID 文件，利用它们来提权。
日常的生产实践还是优先使用 `sudo` 或者 Capabilities 机制来控制权限，SUID 只在必要时使用。

### NameSpace

Docker 有三大核心机制：

- Namespace：隔离进程空间
- Cgroups：限制资源使用
- UnionFS：分层文件系统

那么其中 NameSpace 其实是有很多种的：

- Pid Namespace：进程 ID 隔离
- UTS Namespace：主机名隔离
- Mount Namespace：挂载点隔离
- IPC Namespace：进程间通信隔离
- Network Namespace：网络隔离

接下来的就是我们今天的主角：User Namespace，用户隔离。

## User Namespace

User Namespace 是 Linux 内核提供的一种隔离机制，可以将容器内的用户 ID 映射到宿主机的用户 ID，从而实现用户层面的隔离。
但是，这个 User Namespace **不是默认开启的**，需要在 Docker 的配置文件中进行设置。
也就是说，默认情况下，Docker 里的 root 跟宿主机的 root 就是一回事，被面试官忽悠了，绷。

## Docker 逃逸

## 如何设计一个安全的容器方案

### 安全隐患

未知攻，焉知防？

1. 宿主机的操作系统本身就存在安全隐患
    我们知道，Docker 跟宿主机是共享内核的，所以如果宿主机的内核存在漏洞，那么 Docker 也会受到影响。比如著名的脏牛提权漏洞（CVE-2016-5195）。
2. 容器自身的安全问题
    1. 滥用 Docker API 攻击
    2. Docker 逃逸

// TO be continued...

## 参考

<https://docs.docker.com/engine/security/userns-remap/#about-remapping-and-subordinate-user-and-group-ids>
