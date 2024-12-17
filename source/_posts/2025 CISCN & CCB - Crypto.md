---
title: 2025 CISCN & CCB - Crypto
date: 2024-12-17 18:56:00
tags: [CTF, Crypto]
categories: 题解
---

四个一血，那就是四血，四血就是没血，没血就是菜鸡，所以我是菜鸡。

<!--more-->

## rasnd

签到

```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint
import os

FLAG = os.getenv("FLAG").encode()
flag1 = FLAG[:15]
flag2 = FLAG[15:]

def crypto1():
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    e = 0x10001
    x1=randint(0,2**11)
    y1=randint(0,2**114)
    x2=randint(0,2**11)
    y2=randint(0,2**514)
    hint1=x1*p+y1*q-0x114
    hint2=x2*p+y2*q-0x514
    c = pow(bytes_to_long(flag1), e, n)
    print(n)
    print(c)
    print(hint1)
    print(hint2)


def crypto2():
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    e = 0x10001
    hint = pow(514*p - 114*q, n - p - q, n)
    c = pow(bytes_to_long(flag2),e,n)
    print(n)
    print(c)
    print(hint)
print("==================================================================")
crypto1()
print("==================================================================")
crypto2()
print("==================================================================")
```

Par1 给了
$$
h_1 = x_1p + y_1q \\\\
h_2 = x_2p + y_2q
$$

这里后面硬塞的 0x114 和 0x514 默认加回去了
因为 $x_1$ 和 $x_2$ 比较小，所以可以直接爆出来，然后 $x_2h_1 - x_1h_2$ 就能把 $p$ 消掉，只剩下 $q$ 的倍数，跟 $n$ GCD 一下就分解出来了。

Part2 给了
$$
h = (514p - 114q)^{n - p - q} \pmod n
$$

注意到 $n - p - q = \varphi(n) - 1$，所以 $h$ 就是 $514p - 114q$ 的逆元，这个时候代入 $q = n/p$ 就能化成一个关于 $p$ 的一元二次方程，用通解解出来就行了。
好像看到某支大神队伍用结式搞，有点杀鸡用牛刀了。

## fffffhash

原
[DownUnderCTF2023 fnv](https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/crypto/fnv/solve/solution_joseph_LLL.sage)
有空再来分析
今年的国赛也出了一道 FNV，但是是明确是 7 个字节的，所以可以直接 MITM，也就是中间相遇搞出来。

## LWEWL

双原合一
Dicectf2023 membrane
NSSCTF Round18 New Year Ring3
也是有空再来分析

## babypqc

### 极简非预期

第一次输入 `0`
第二次输入 `[]`
你就有 1/16 的概率拿到 flag

### 正经解法

首先是打一个 MT19937，题目给的随机数加起来刚好是 19968 bit 的，所以需要利用 N （一个 list）把 p q 分解出来，这部分可以用 AGCD 搞出来。
搞到这 m 就还原出来了，塞给他签名，就拿到了一个正确的签名，再交回去，answers 就是 1，num 是 0-15 的随机数，赌他随出 1 就行。
也就是这时候我发现随出 0 也行，也就是上面的极简非预期解法。。。无语了
打出 MT19937 后 tmp 就全知道了，$s_1$ 由于是只有 512 个非零元素，所以可以直接 `solve_right` 解出来，但是 $s_2$ 是满的，应该要用格搞一搞。

作业没写完，有空再来补。
