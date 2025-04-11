---
title: Java 基础概念
date: 2025-04-09 20:01:00
tags: [Java]
categories: 环境搭建
---

捋一下 Java 是怎么个事
<!--more-->

## 前言

想复现一下关于 Log4j 的近古漏洞 CVE-2021-44228，并接触一下 Java 反序列化，但是哥们一直没写过 Java，所以还是先了解一下这门语言先吧。

## JRE JDK JVM

JRE 全称 Java Runtime Environment，Java 运行环境。它是 Java 的运行时环境，包含了 Java 虚拟机（JVM）和 Java 核心类库。JRE 是运行 Java 程序的必要条件，但不包含开发工具。
JDK 全称 Java Development Kit，Java 开发工具包。它是 Java 的开发环境，包含了 JRE 和一些开发工具，如编译器（javac）、调试器（jdb）等。JDK 是开发 Java 程序的必要条件。
JVM 全称 Java Virtual Machine，Java 虚拟机，负责执行 Java 字节码。JVM 是 JRE 的一部分，是 Java 程序运行的核心组件。

也就是说，JDK = JRE + 开发/调试工具，JRE = JVM + 核心类库。

## Java 版本

如果说还有一个令人迷惑的东西，那就是 Java 的版本了，其版本命名十分怪异，与 Python 之类规律版本命名方式完全不同。
光是平时就看见 Java8 和 Java22 之类的了。

Java 有三个主要版本：

- Java SE（Standard Edition）：标准版，适用于桌面和服务器应用程序。
- Java EE（Enterprise Edition）：企业版，适用于大型企业级应用程序。
- Java ME（Micro Edition）：微型版，适用于嵌入式和移动设备。

而我们平时只需要关注 Java SE 就可以了。
然后提到 JDK，有一个简单的对应关系：一个 Java 版本对应一个 JDK 版本。

### 发展历程

最古早的时候，也就是 1996 年，Java 1.0 发布了，同时对应着 JDK 1.0。
那按道理来说下面就是 Java 1.1 和 JDK 1.1，然后是 Java 1.2 和 JDK 1.2，然后一直这样。
哎，他不
98 年，Java 1.1 的下一个版本变成了 J2SE 1.2，JDK 倒是一保持命名，也是 JDK 1.2。
然后到 04 年的时候，原本版本号应该是 J2SE 1.5，但是由于 Java 版本又有一个大便化，哎，改成了 Java SE 5.0，JDK 命令依旧不变，还是 JDK 1.5。

这时候你觉得 JDK 命名还挺稳定的
然而我们把时间拉到 2018 年，Java SE 10 发布，JDK 不叫 JDK 1.10 了，叫 JDK 10。
这种命名也一直延续至今，我写这篇文章的时候已经是 Java SE 24，这个版本也会在今年（2025 年）9 月停止更新，届时会发布一个 LTS（Long Term Support，即长期支持）版本 —— Java SE 25。

有几个 LTS 版本，分别是 8、11、17 和 21。

## 参考

[What is the difference between JDK and JRE?](https://stackoverflow.com/questions/1906445/what-is-the-difference-between-jdk-and-jre)
[一文彻底搞懂令人疑惑的Java和JDK的版本命名！](https://blog.csdn.net/sinat_33921105/article/details/117513645)
