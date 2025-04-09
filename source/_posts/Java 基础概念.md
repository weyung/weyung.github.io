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

## 参考

[Stack Overflow - What is the difference between JDK and JRE?](https://stackoverflow.com/questions/1906445/what-is-the-difference-between-jdk-and-jre)
[CSDN - 一文彻底搞懂令人疑惑的Java和JDK的版本命名！](https://blog.csdn.net/sinat_33921105/article/details/117513645)
