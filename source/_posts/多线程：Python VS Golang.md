---
title: 多线程：Python VS Golang
date: 2025-03-30 13:34:00
tags: [Python, Golang]
categories: 学习
---

Golang 的牛皮之处
<!--more-->

## 前言

平时做密码题经常会用到多线程加速爆破，但是一直没仔细研究过这方面的东西。

## Review: multiprocessing VS multithreading

相信大家都听说过线程和进程，也相信有一部分读者跟我一样常常把它们搞混——这中文翻译得，都有一个程字就是说。
操作系统是有讲过的，**进程（Process）是资源分配的基本单位，线程（Thread）则是 CPU 调度的基本单位。**
我们再详细分析他们的区别：
进程由于其资源是独立的，所以进程之间的通信需要 IPC（Inter-Process Communication）机制，比如管道、消息队列、共享内存等；而线程由于其资源是共享的，所以线程之间的通信就简单多了，直接读写共享变量就行了，创建和切换线程的开销也比进程小得多。

DeepSeek 的类比比较恰当：
**进程**像一个“工厂”：拥有独立的场地（内存）、设备（资源）和工人（线程）。
**线程**像工厂内的“工人”：共享工厂的资源，协作完成生产任务。
**多工厂（多进程）**：需要复制多套场地和设备，成本高，但安全隔离。
**单工厂多工人（多线程）**：效率高但需协调工人避免冲突。

相应地，并发和并行也是有说法的：**多进程对应并行，多线程对应并发**。多进程通过在不同的核上运行任务来实现并行，而多线程则是通过在同一个核上切换任务来实现并发。

## 为什么说 Python 的多线程是伪多线程

一切都缘于 GIL（Global Interpreter Lock），也就是 Python 的全局解释器锁，作为保护访问 Python 对象的线程安全的一种机制，**GIL 使得同一时刻只有一个线程在执行 Python 字节码**，一个线程在执行 Python 字节码时，其他线程只能等待，即线程是交替执行的。

## 总结

I/O 密集型任务使用多线程，CPU 密集型任务使用多进程。

## Golang 又是怎么个事

// To be continued...

## 参考

<https://zm-j.github.io/2022/11/21/python-multiprocessing/>
<https://medium.com/capital-one-tech/python-guide-using-multiprocessing-versus-multithreading-55c4ea1788cd>
<https://zhuanlan.zhihu.com/p/633279726>
