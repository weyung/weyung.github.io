---
title: SSRF & CSRF
date: 2025-04-03 16:14:00
tags: [CTF, Web, 渗透]
categories: 学习
---

朝花夕拾。
<!--more-->

## 前言

遥远的三年前就被 Matrix 面试问过 CSRF，如今子弹正中眉心了。

## SSRF

### SSRF 简介

SSRF（Server-Side Request Forgery）中文翻译过来就是服务器端请求伪造攻击。

以下为 CTFShow 上的题目：

### web351 - web355

题目 web351 直接访问代码如下：

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
?>
```

再测试一下目录，发现存在 `/flag.php` 文件，访问提示 `非本地用户禁止访问`，说明题目意思就是利用 `index.php` 来构造 SSRF 攻击访问 `/flag.php`。
搜索发现 `curl_exec()` 函数可以使用 `file://` 协议来读取本地文件，直接构造请求：

```bash
curl -X POST -d "url=file:/var/www/html/flag.php" http://f9eb43c2-526b-4868-9513-ec378c84383c.challenge.ctf.show/
```

即可查看到 `/flag.php` 的内容，同样也能读取 `/etc/passwd` 等文件。

web352 直接访问代码如下：

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
if(!preg_match('/localhost|127.0.0/')){
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
}
else{
    die('hacker');
}
}
else{
    die('hacker');
}
?>
```

题目意思框定了要求的协议为 `http` 和 `https`，并且不能包含 `localhost` 和 `127.0.0`，但是仔细观察可以发现 `preg_match()` 函数只有 pattern 参数，根本没有起到检测的作用，直接传 `http://127.0.0.1/flag.php` 也能访问到 `/flag.php` 的内容，预期解应该是传长整数型的 IP，即 `http://2130706433/flag.php`，当然直接传 `0x7f000001` 也是没有问题的。

web353 直接访问代码如下：

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
if(!preg_match('/localhost|127\.0\.|\。/i', $url)){
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
}
else{
    die('hacker');
}
}
else{
    die('hacker');
}
?>
```

。。。直接就是上一题的 revenge，但是聪明的出题人你知不知道回送地址是 127.0.0.0/8 呢
我直接一个 127.2.0.1 你不炸了吗

web354 做得比较绝了，直接 `preg_match('/localhost|1|0|。/i', $url)`，我想一会直接搞了个比较淫荡的方法，经过测试这个环境是通网的，那直接用手头的域名解析到 127.0.0.1 即可，`http://local.weyung.cc/flag.php` 就行了，最后一看 wp 好像这还确实是预期解，绷。

web 356 直接访问代码如下：

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
$host=$x['host'];
if((strlen($host)<=5)){
$ch=curl_init($url);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result=curl_exec($ch);
curl_close($ch);
echo ($result);
}
else{
    die('hacker');
}
}
else{
    die('hacker');
}
?>
```

把 host 长度限制在 5 个字符以内，想不出来了，看 wp 的话可以 `http://0/flag.php`，因为在 Linux 中 0 指向 localhost，也可以 `http://127.1/flag.php`，当然我觉得有钱买个更短的域名应该也行就是了（

### web356 - web360

web356 直接就是把长度限制调成 3 了，应该就是只能用 `http://0/flag.php` 了。

web357 直接访问代码如下：

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if($x['scheme']==='http'||$x['scheme']==='https'){
$ip = gethostbyname($x['host']);
echo '</br>'.$ip.'</br>';
if(!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    die('ip!');
}


echo file_get_contents($_POST['url']);
}
else{
    die('scheme');
}
?>
```

这个过滤也做得比较绝，直接把本地 IP 都封死了，只能在公网服务器做一个 302 重定向

```php
<?php header("Location: http://127.0.0.1/flag.php", true, 302);?>
```

然后访问这个公网 IP 即可。

web358 直接访问代码如下：

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$url=$_POST['url'];
$x=parse_url($url);
if(preg_match('/^http:\/\/ctf\..*show$/i',$url)){
    echo file_get_contents($url);
}
```

这个除了搞一个 ctf 开头的域名以外我也想不出来方法了，看 wp 可以构造 `http://ctf.@127.0.0.1/flag.php?show` 这样的 payload，直接把 `ctf.` 作为 username 传入。

web359 开始就是正经题目了，访问得到一个登录页面

// To be continued...

## CSRF

## 参考

<https://xz.aliyun.com/news/10663>
