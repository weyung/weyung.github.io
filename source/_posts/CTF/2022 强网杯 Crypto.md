---
title: 2022 强网杯 Crypto
date: 2022-08-08 10:03:00
tags: [CTF, Crypto]
categories: 题解
---

当场做是做不出来的，赛后分析学学吧，不定期更新
<!--more-->

## Lattice

```python
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Cipher import AES
from base64 import b64encode
from hashlib import *
from secret import flag
import signal

n = 75
m = 150
r = 10
N = 126633165554229521438977290762059361297987250739820462036000284719563379254544315991201997343356439034674007770120263341747898897565056619503383631412169301973302667340133958109

def gen(n, m, r, N):
    t1 = [ZZ.random_element(-2^15, 2^15) for _ in range(n*m)]
    t2 = [ZZ.random_element(N) for _ in range(r*n)]
    B = matrix(ZZ, n, m, t1)        # B为75*150的矩阵
    L = IntegerLattice(B)
    A = matrix(ZZ, r, n, t2)        # A为10*75的矩阵
    C = (A * B) % N                 # C为10*150的矩阵
    return L, C

def pad(s):
    return s + (16 - len(s) % 16) * b"\x00"

signal.alarm(60)
token = input("team token:").strip().encode()
L, C = gen(n, m, r, N)
print(C)
key = sha256(str(L.reduced_basis[0]).encode()).digest()
aes = AES.new(key, AES.MODE_ECB)
ct = b64encode(aes.encrypt(pad(flag))).decode()
print(ct)
```

题目生成了一个元素在 $[-2^{15},2^{15}]$ 间的矩阵 $B_{75\times150}$ ，和 $Z_N$ 上的矩阵 $A_{10\times75}$ 。然后给了一个两矩阵相乘再模 $N$ 的结果 $C$ ，即 $C=AB\pmod N$ ，需要我们恢复出原来格$B$的最短向量。

比赛时尝试过构造 $\left[ C \enspace NI\right]^T$ ，跑LLL出来的结果很差， BKZ 的话一晚上啥也没出来。。
赛后只找到 Nu1L 队的 wp ，but 也只有个 exp ，一句解释都没，像我这样的菜鸡分析起来就十分吃力了，但聊胜于无嘛，其他几个队连个 wp 都不放呜呜呜。

exp 中构造了一个 $m+r=150+10=160$ 维的方阵 $A$ 如下：
$$
A=
\left(
\begin{array}{cccc|cccc}
1 & 0 & \cdots & 0 & 2^{200}\cdot c_{0,0} & 2^{200}\cdot c_{1,0} & \cdots & 2^{200}\cdot c_{9,0} \\\\
0 & 1 & \cdots & 0 & 2^{200}\cdot c_{0,1} & 2^{200}\cdot c_{1,1} & \cdots & 0 \\\\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \ddots & 0 \\\\
0 & 0 & \cdots & 1 & 2^{200}\cdot c_{0,149} & 2^{200}\cdot c_{1,149} & \cdots & 2^{200}\cdot c_{9,149} \\\\ \hline
0 & 0 & \cdots & 0 & 2^{200}\cdot N & 0 & \cdots & 0 \\\\
0 & 0 & \cdots & 0 & 0 & 2^{200}\cdot N & \cdots & 0 \\\\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \ddots & \vdots \\\\
0 & 0 & \cdots & 0 & 0 & 0 & \cdots & 2^{200}\cdot N
\end{array}
\right)
$$
可以看到 $A$ 左上角为一个 $150$ 维的单位阵，左下角为零阵，右上角为 $C$ 的转置数乘 $2^{200}$ ，右下角为一个 $10$ 维的单位阵数乘 $2^{200}\cdot N$ ，这里乘不乘 $2^{200}$ 得到的结果都是一样的，但神奇的是不乘的话 LLL 耗时会长一些。
$A$ 跑一遍 LLL 后，取结果的左上角 $75\times150$ 矩阵，记为 $B$ ，取 $B$ 的核记为 $D$ ，最后 $D$ 跑一遍 BKZ 后的最短向量即为所求。
> 这里涉及到矩阵的核的概念，核也叫矩阵的零空间，比如 $M$ 的核是方程 $Mx=0$ 的所有解 $x$ 的集合。

那么就不难看出有 $BD^T=O$ ，即 $B^TD=O$
至于 $C$ 为什么左边要拼接一个单位阵，回忆你已经遗忘的线性代数，这种操作是不是似曾相识？没错说的就是矩阵的求逆，求逆矩阵除了伴随矩阵法，还有一种方法就是初等变换法。
例如如下一个矩阵求逆
$$
M=
\begin{pmatrix}
1 & -4 & -3 \\\\
1 & -5 & -3 \\\\
-1 & 6 & 4
\end{pmatrix}
$$
在右边补上一个单位阵，得到
$$
A=
\left(
\begin{array}{ccc|ccc}
1 & -4 & -3 & 1 & 0 & 0 \\\\
1 & -5 & -3 & 0 & 1 & 0 \\\\
-1 & 6 & 4 & 0 & 0 & 1
\end{array}
\right)
\stackrel{初等行变换}{\longrightarrow}
\left(
\begin{array}{ccc|ccc}
1 & 0 & 0 & 2 & 2 & 3 \\\\
0 & 1 & 0 & 1 & -1 & 0 \\\\
0 & 0 & 1 & -1 & 2 & 1
\end{array}
\right)
$$
此时右边的矩阵 $M^{-1}$ 即为所求
究其原理，在进行初等行变换的时候，右边的矩阵“记录”下了我们的操作，可以表示为
$$
M^{-1}
\left[
    M\enspace I
\right] =
\left[
    I\enspace M^{-1}
\right]
$$
回到题目中来，有
$$
L
\left[
    I \enspace C^T
\right]
 \enspace \% \enspace N=
\left[
\begin{matrix}
    B & O \\\\
    R & S
\end{matrix}
\right]
$$
至于右上角为何是一个 $75\times10$ 的零阵，我也不知道，但 exp 既然这么断言，姑且就这么认为先，那么我们就推测
$$
L=
\left[
\begin{matrix}
    B \\\\
    R
\end{matrix}
\right]
,LC^T=
\left[
\begin{matrix}
    O \\\\
    S
\end{matrix}
\right]
\pmod N
$$
即有
$$
\left[
\begin{matrix}
    B \\\\
    R
\end{matrix}
\right]C^T=
\left[
\begin{matrix}
    O \\\\
    S
\end{matrix}
\right]\pmod N
$$
得到 $BC^T=O\pmod N$ ，结合上面 $BD^T=O$ ，推测。。。推测不出来了，然后结合队里大手子的分析如下

记题目中给出的两个矩阵为 $\mathcal{A}$和$\mathcal{B}$ ，有
 $\mathcal{A}\mathcal{B} = C\pmod N$
若有 $B(\mathcal{A}\mathcal{B})^T = BC^T = O\pmod N$ ，则 $B$ 和 $C^T$ 互为左右零空间。
因此可以通过构造格 $L$ ，使得对格 $L$ 进行格基规约后可以得到一组基 $B$ 满足 $BC^T = O\pmod N$ ，即 $B$ 的基就是 $C^T$ 在模 $N$ 下的一个左零空间。
接下来对 $B$ 求解其零空间 $D^T$ 就得到了 $(\mathcal{A}\mathcal{B})^T$ 所在的那个空间上了，这里从有限域化为整数域，即 $D=\mathcal{A}\mathcal{B}$ ，然后因为 $\mathcal{B}$ 中所求的行向量是一个短向量，且矩阵 $D^T$ 的行向量是 $\mathcal{B}$ 的行向量的线性组合，因此对 $D^T$ 进行格基规约算法就可以把 $\mathcal{B}$ 的短向量给恢复出来。

至此已经有明悟的感觉，但仍是有少许不解，消化一段时间吧。
