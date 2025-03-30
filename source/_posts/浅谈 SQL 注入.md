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

可以看到，`conn.PreparedStatement()` 函数直接把 SQL

// To be continued...

## 参考

<https://www.zhihu.com/question/52869762>
