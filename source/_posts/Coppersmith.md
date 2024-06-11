---
title: Coppersmith
date: 2022-10-15 19:30:00
tags: [数学, 抽象代数, Crypto, 论文]
categories: 数学
---

研究一些多元 Coppersmith

<!--more-->

## 前言

不知不觉学密码有半年了，从最开始的 RSA 到格再到奇奇怪怪的东西，不禁感慨数学确实有趣。
之前的 MRCTF 的题有道三元 Coppersmith ，可惜当时水平太过低微，既做不出来也看不懂 exp ，如今再回来补这个坑，就差不多可以往生 pwn 了。

## 后记

这篇文章搁了很久，pwn 由于一些原因也没怎么做，还是在密码里打点小工。刚好天枢的 CTF 有一道 Coppersmith，吃了没基础的亏，论文都看不懂。

## Coppersmith 的大致思想

可以参考 Tover 爷的[这篇文章](https://tover.xyz/p/d3factor-coppersmith/#%E6%A8%A1N%E4%B8%8B%E7%9A%84%E4%BA%8C%E5%85%83Coppersmith)。

### 模根与整根

RSA 的许多攻击都可以化成解模根的问题，而所谓解模根就是方程在模数 $N$ 下的解。这时候直接解是不现实的，就需要用到 Coppersmith 方法。
解模根的关键就是 **Howgrave-Graham** 定理：
令 $h(x_1,...,x_n) \in Z[x_1,...,x_n]$ 为一个至多含 $\omega$ 个单项式的整数多项式，若满足
$$
h(x_1^{(0)},...,x_n^{(0)}) \equiv 0 \mod N^m \enspace for\enspace some\enspace |x_1^{(0)}| < X_1,\dots,|x_n^{(0)}| < X_n ,\enspace and  \\\\
||h(x_1X_1,\dots,x_nX_n)|| < \frac{N^m}{\sqrt{\omega}}
$$
则 $h(x_1^{(0)},...,x_n^{(0)}) = 0$ 在整数域上成立。

不难看出，这个定理实际是将模方程转化成我们所常见的整数方程，这样，我们就可以用一些常见的方法（如牛顿迭代法）来求解了。

如 GF(323) 上的方程
$$
F(x) = x^2 + 33x + 215 \equiv 0 \pmod{323}
$$
由韦达定理就能看出，这个方程在整数域下是解不出来实根的，但是我们稍微变换一下，变为如下形式，
记 $M = 323$
$$
G(x) = 9F(x) - M(x+6) = 9x^2 - 26x - 3
$$
注意，$G(x) \equiv 0 \pmod{M}$ 仍是成立的。
但是这个时候，肉眼分解 $G(x) = (x-3)(9x+1)$ 就能得到根 $x_0=3$，而这个根代入原始方程也是成立的。

Coppersmith 就是利用这个思想，往方程加入一些模 $M$ 为零的项，使得方程满足 Howgrave-Graham 定理的条件，然后再用整数域的方法求解。

## 单变量 Coppersmith 的实现

一个比较基础是方法是构造一个简单的矩阵跑 LLL。直接上例子：

$$
F(x) = x^3 + 10x^2 + 5000x − 222
$$

我们可以构造矩阵

$$
B=
\begin{pmatrix}
M & 0 & 0 & 0 \\\\
0 & MX & 0 & 0 \\\\
0 & 0 & MX^2 & 0 \\\\
-222 & 5000X & 10X^2 & X^3
\end{pmatrix}
$$

可以理解成 LLL 的过程中用前面三行对最后一行进行了一些加减操作，使得最后一行的系数变得很小，而实际上系数变小就是为了满足 Howgrave-Graham 定理的界。

LLL 后我们得到向量 $(444, 10, −2000, −2000)$，对应的多项式为 $G(x) = 444+x-20x^2-2x^3$，这个多项式在整数域上的根 $x_0=4$ 即为原方程的根。

然而以上的方法需要满足 $M^dX^{d(d+1)/2} =\det(L) < M^{d+1}$，更精确来说是 $2^{d/4}M^{d/(d+1)}X^{d/2} < M/\sqrt{d + 1}$（证明不难，即 LLL 得到的最短向量小于 HG 定理的界），可以看出 $X$ 越小这个条件越容易满足，但是我们的研究通常是把 $X$ 的界往上扩的，这时我们就可以加一些 x-shift 的多项式(关于这个词，总感觉翻译成 x 的移位多项式比较怪，本文就保留原英文称谓了)。

如果你细心去算了，就会发现上面的例子其实是不符合条件的，因为 LLL 给出的是最坏的界，我们算条件也是用这个最坏的界，上面恰好得到了一个更好（即更短）的向量。

感觉这篇文又要鸽了，没看懂他例子的格是怎么造出来的。

## 二元 Coppersmith

### 结式

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
- [Coppersmith’s Method and Related Applications](https://www.math.auckland.ac.nz/~sgal018/crypto-book/ch19.pdf)
- [lord. Way to CopperSmith](https://lord-riot.github.io/2021/01/06/Way-to-CopperSmith/)
