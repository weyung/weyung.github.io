---
title: Coppersmith
date: 2022-10-15 19:30:00
tags: [数学, 抽象代数, 密码学, 论文]
categories: 数学
---

研究一些多元 Coppersmith

<!--more-->

## 前言

不知不觉学密码有半年了，从最开始的 RSA 到格再到奇奇怪怪的东西，不禁感慨数学确实有趣。
之前的 MRCTF 的题有道三元 Coppersmith ，可惜当时水平太过低微，既做不出来也看不懂 exp ，如今再回来补这个坑，就差不多可以往生 pwn 了。

## Coppersmith 的大致思想

可以参考 Tover 爷的[这篇文章](https://tover.xyz/p/d3factor-coppersmith/#%E6%A8%A1N%E4%B8%8B%E7%9A%84%E4%BA%8C%E5%85%83Coppersmith)。

### 模根

解模根的关键就是 **Howgrave-Graham** 定理：
令 $h(x_1,...,x_n) \in Z[x_1,...,x_n]$ 为一个至多含 $\omega$ 个单项式的整数多项式，若满足
$$
h(x_1^{(0)},...,x_n^{(0)}) \equiv 0 \mod N^m \enspace for\enspace some\enspace |x_1^{(0)}| < X_1,\dots,|x_n^{(0)}| < X_n ,\enspace and  \\\\
||h(x_1X_1,\dots,x_nX_n)|| < \frac{N^m}{\sqrt{\omega}}
$$
则 $h(x_1^{(0)},...,x_n^{(0)}) = 0$ 在整数域上成立。

未完待续...

### 整根

似乎是加个合适的模数？

## 三元 Coppersmith

### 参数解释

论文里 $X,Y$ 和 $Z$ 不难理解是三个变量对应的界，但除此之外还有 $W,\tau$ 和 $m$ 的选取，这也是我当前很迷糊的点，下面简单探讨一下。

首先是最简单的 $W$ ，论文明确给出 $W=||f(x_1X_n,\dots,x_nX_n)||\_\infty$ ，而 $||f(x_1,\dots,x_n)||_{\infty}$ 的意思就是多项式的最大系数，所以 $W$ 就是多项式对各 $x$ 进行 $Xx$ 代入后的最大系数。如 $f=2x^2+3x+4$ ， $X=2$ ，则 $||f(x_1X_n,\dots,x_nX_n)||=8x^2+6x+4$ ，显然最大系数在 $x^2$ 那，即 $W=8$ 。
~~然后 $\tau$ 和 $m$ 目前我也不知道咋算（）~~

## 杂谈

直到现在才反应过来 paper 的引用名中后面的数字是年份（）

## 参考

- [知乎 -「:=」和「=:」的区别是什么？](https://www.zhihu.com/question/29969904)
- [Santanu Sarkar and Subhamoy Maitra. Some Applications of Lattice Based Root Finding Techniques](https://link.springer.com/chapter/10.1007/11935230_18)
- [[ELL06] E. Jochemsz and A. May. A strategy for finding roots of multivariate polynomials with new applications in attacking RSA variants, Asiacrypt 2006, LNCS 4284, pp. 267–282, 2006.](https://www.cs.umd.edu/~gasarch/TOPICS/attackingRSA.pdf)
