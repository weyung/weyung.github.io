---
title: Reed-Solomon 纠错码
date: 2022-09-17T18:22:15+08:00
tags: [数学,Crypto,抽象代数,CTF]
categories: 题解
---

终于有时间整理一下了，爆破毕竟还是太粗鲁了。
<!--more-->

羊城杯的一道题，题目中只破坏了消息的随机两个位置，消息又在 256 以内，所以可以直接暴力枚举。
下面探寻优雅点的解法。

## 编码

先来看看题目的代码，如下是编码的核心函数：

```python
m = 257
F = Zmod(m)
alpha = F(223)
PR.<x> = PolynomialRing(F)
gx = (x - alpha ^ 0) * (x - alpha ^ 1) * (x - alpha ^ 2) * (x - alpha ^ 3)

def encode_block(message):
    assert isinstance(message, list)

    f = PR([0] * 4 + message)
    px = f % gx
    mx = f - px
    c = [_ for _ in mx]
    return c + (8 - len(c)) * [0]
```

分析一下，代码中取一个生成多项式 $g(x)=(x-\alpha^0)(x-\alpha^1)(x-\alpha^2)(x-\alpha^3)$ ，然后将消息多项式 $M(x)$ 模 $g(x)$ ，得到余数多项式 $P(x)$ ，最后得到编码后的消息 $S(x)=M(x)-P(x)$ 。这时有 $S(x)\equiv 0\mod g(x)$ 。
这里解释一下各个参数，当时我也是看了好久 sagemath 的文档也没搞懂。
生成多项式 $g(x)=\prod\limits_{j=1}^{n-k}(x-\alpha^j)$
// TODO

## 解码

照着[这篇文章](https://zhuanlan.zhihu.com/p/104306038)搓了个 PGZ 解码器，代码如下：

```python
def decode_block(r_x):
    S = [PR(r_x)(alpha^i) for i in range(4)]
    nu = 2
    A = matrix(F,nu,nu)
    for i in range(nu):
        for j in range(nu):
            A[i,j] = S[i+j]
    b = vector(F,[-S[nu+i] for i in range(nu)])
    x = list(A.solve_right(b))
    x.append(1)
    x.reverse()
    Lambda = PR(x)
    I = []
    for i in range(8):
        if Lambda(alpha^(-i))==0:
            I.append(i)
    I = I + [0] * (2 - len(I))
    X = [alpha^I[i] for i in range(2)]
    A = matrix(F,2,2)
    for i in range(2):
        for j in range(2):
            A[i,j] = X[j]^i
    b = list(A.solve_right(vector(F,S[:2])))
    for i in range(len(I)):
        r_x[I[i]] -= b[i]
    return r_x[4:]
```

## 参考

* <https://zhuanlan.zhihu.com/p/104306038>
* <https://eprint.iacr.org/2017/733.pdf>
