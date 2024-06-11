---
title: 2023 BricsCTF - random
date: 2023-09-30 20:58:00
tags: [CTF, Crypto]
categories: 题解
---

持续复健中。。。
<!--more-->
********************************

## 题目

密码太狠了，这题也是 0 解。
给了一个 `Program.cs` 如下：

```csharp
var rng = new Random();
byte[] Encrypt(byte[] x) => x.Select(a=>(byte)(a^rng.Next(256))).ToArray();
Console.WriteLine(Convert.ToHexString(Encrypt(File.ReadAllBytes("flag.txt"))));
Console.WriteLine(Convert.ToHexString(Encrypt(new byte[2000])));
```

题文如下:

```plain
This is xoshiro256** 1.0, one of our all-purpose, rock-solid generators. It has excellent (sub-ns) speed, a state (256 bits) that is large enough for any parallel application, and it passes all tests we are aware of.
```

## 分析

在 GitHub 找到了 `xoshiro256** 1.0` 的源码，状态更新函数如下：

```csharp
ulong t = _s1 << 17;
_s2 ^= _s0;
_s3 ^= _s1;
_s1 ^= _s2;
_s0 ^= _s3;
_s2 ^= t;
_s3 = BitOperations.RotateLeft(_s3, 45);
```

提出 result 的函数如下：

```csharp
result = BitOperations.RotateLeft(_s1 * 5, 7) * 9
```

看起来也是线性的，一开始想尝试像 MT19937 一样造个状态转移矩阵出来，但是理论上状态转移矩阵是 256 维的，而他给出了 8*2000=16000 个 bit，多太多了，结果也失败了。

## 题解

用 Copilot 翻译一下官方的 wp 先。

当没有指定 `seed` 时，64 位机器上的最新版本的 C# 使用 xoshiro256** PRNG：

```csharp
internal ulong NextUInt64()
{
    ulong s0 = _s0, s1 = _s1, s2 = _s2, s3 = _s3;

    ulong result = BitOperations.RotateLeft(s1 * 5, 7) * 9;
    ulong t = s1 << 17;

    s2 ^= s0;
    s3 ^= s1;
    s1 ^= s2;
    s0 ^= s3;

    s2 ^= t;
    s3 = BitOperations.RotateLeft(s3, 45);

    _s0 = s0;
    _s1 = s1;
    _s2 = s2;
    _s3 = s3;

    return result;
}
```

这个 RNG 的状态转移函数是 GF(2) 下的线性函数，而 `result` 是 `s1` 的非线性函数。如果我们能得到 NextUInt64 的精确返回值，那么就能轻松破解 RNG。我们可以通过乘以乘法逆元来将 `s1` 的每一位表示为初始状态的线性函数，构建一个线性方程组并解出初始状态。但是这道题给出的是 `rng.Next(256)` 的输出，就是只保留 `result` 的高 8 位（草，当时以为是低 8 位）。这样就无法从中获得 `s1` 的任何信息。

我们还可以检查在 `result` 的值确定的情况下，`s1` 的位之间是否存在固定的线性（或仿射）关系：

```python
from sage.all import *
import random
def f(x):
    x *= 5
    x %= 2**64
    x = (x << 7) | (x >> (64 - 7))
    x %= 2**64
    x *= 9
    x %= 2**64
    return x >> 56
vectors = [[] for _ in range(256)]
for i in range(100000):
    a = random.getrandbits(64)
    v = vector(GF(2), '1' + bin(a)[2:].zfill(64))
    vectors[f(a)].append(v)
for i in range(256):
    mat = matrix(GF(2), vectors[i])
    print(mat.rank(), len(vectors[i]))
```

对于每个 `result` 的值，这个程序生成了一些随机的 `s1` 的可能值，然后计算由这些值的位（和一个 1 来处理异或 1 的子集）生成的矩阵的秩。所有 256 个矩阵的秩都是 65，这意味着向量是独立的，对于任何 `result` 的值都不存在固定的仿射关系，因此无法从中获得任何信息。

> 这里的秩应该是倾向列秩，即他的意思是对于 `s1` 的 bits，不存在哪个 bit 能由其他 bits 线性组合（或者线性组合再取反）后得到。不是很明白检查这个有啥用。

可以获得**概率**线性关系，但是解线性系统就变成了 LPN（Learning Parity with Noise, 带噪声的学习奇偶校验）问题，据我所知，目前还没有足够快的算法。

> LPN 问题具体来说是这样的：给定一个二进制矩阵 $A$ 和一个噪声向量 $e$，求解未知的二进制向量 $s$ 使得 $As + e = b\pmod2$。其中，$A$ 是一个随机生成的二进制矩阵，$s$ 是一个未知的二进制向量，$e$ 是一个含有少量随机错误的二进制向量，$b$ 是我们观测到的结果向量。噪声向量 $e$ 的存在使得这个问题变得非常困难。

这里可能有多个解；我找到的解是检查**二次关系**：

> 这里不是很懂，为啥没有线性关系就能有二次关系。

- 假设 `result` 的值是固定的，可能存在非平凡的次数 <=2 的布尔函数，当在 `s1` 上取值时总是为真。函数 `f(...) = 1` 符合这个描述，但是不值得考虑，因为它不提供任何信息。
- 函数可以写成 $$f(x_1, \dots, x_{64}) = k_0 + \sum_{i} k_i x_i + \sum_{i \le j} k_{ij} x_i x_j,$$ 并且 `s1` 的每一位都可以表示为 $\sum_i k_i s_i$，其中 s 是初始状态。
- 我们可以直接将 `s1` 的位的表达式代入 $f$，展开括号并获得对初始状态为真的二次方程。

我们仍然需要找到这些二次布尔函数。这可以通过生成许多随机的 64 位向量来完成，这些向量对应于给定的 `result >> 56` 的值，为它们中的每一个计算所有 $1 + 64 + \frac{64 \cdot 63}2 = 2081$ 个单项式，并找到矩阵的核。实现在 `gen_rels.cpp` 中，它平均每个输出字节找到 23 个方程。

这使我们能够在 256 个变量上创建一个超定的二次方程组，它的初始状态是它的（希望是唯一的）解。我用来解决它的算法是线性化：我们可以将每个单项式（如 $x_1x_2$）视为单独的变量。然后我们将有一个线性方程组，其中 $1 + 256 + \frac{256 \cdot 255}2 = 32897$ 个变量，可以使用 M4RI 解决。实现在 `hax.cpp` 中，它期望 `gen_rels.cpp` 的输出在文件 `list_rels` 中，`output.txt` 的十六进制解码版本在文件 `out_bin` 中。

> M4RI（Method of Four Russians for Inversion，四俄方法的逆运算方法）是一种针对有限域 GF(2) 上的矩阵运算（特别是矩阵求逆）的高效算法。它的名字来源于一种叫做“四俄罗斯算法”的技术，该技术是为了加速某些基本运算而发明的。
在 Debian 系中可通过 `sudo apt-get install libm4ri-dev` 安装 M4RI 库。

`gen_rel.cpp` 如下：

```c++
#include <vector>
#include <random>
#include <m4ri/m4ri.h>
// we need to find degree 2 relations that hold certainly
uint8_t f(uint64_t x)
{
    x *= 5;
    x = (x << 7) | (x >> (64 - 7));
    x *= 9;
    return x >> 56;
}
void process(uint8_t tgt)
{
    std::mt19937_64 mt;
    size_t n_cols = 1;
    n_cols += 64;
    n_cols += 64 * 63 / 2;
    fprintf(stderr, "%zu monomials\n", n_cols);
    mzd_t *A = mzd_init(20000, n_cols);
    for(size_t ri = 0; ri < A->nrows; ri++)
    {
        uint64_t x = 0;
        do
            x = mt();
        while(f(x) != tgt);
        //printf("%zu\n", x);
        size_t mi = 0;
        mzd_write_bit(A, ri, mi++, 1);
        for(size_t i = 0; i < 64; i++)
            mzd_write_bit(A, ri, mi++, (x >> i) & 1);
        for(size_t i = 0; i < 64; i++)
        for(size_t j = 0; j < i; j++)
            mzd_write_bit(A, ri, mi++, (x >> i) & (x >> j) & 1);
        assert(mi == n_cols);
    }
    mzd_t* ker = mzd_kernel_left_pluq(A, 0);
    fprintf(stderr, "mat dim: %zu rows, %zu cols\n", A->nrows, A->ncols);
    fprintf(stderr, "ker dim: %zu rows, %zu cols\n", ker->nrows, ker->ncols);
    mzd_t* tker = mzd_transpose(nullptr, ker);
    fprintf(stderr, "tker dim: %zu rows, %zu cols\n", tker->nrows, tker->ncols);
    mzd_free(A);
    mzd_free(ker);
    /*
    // check again that the relations are certain (not very fast)
    for(size_t ri = 0; ri < tker->nrows; ri++)
    {
        for(size_t _ = 0; _ < 100000; _++)
        {
            uint64_t x = 0;
            do
                x = mt();
            while(f(x) != tgt);
            //printf("%zu\n", x);
            size_t nm = 0;
            size_t mi = 0;
            nm ^= mzd_read_bit(tker, ri, mi++);
            for(size_t i = 0; i < 64; i++)
                nm ^= mzd_read_bit(tker, ri, mi++) & (x >> i) & 1;
            for(size_t i = 0; i < 64; i++)
            for(size_t j = 0; j < i; j++)
                nm ^= mzd_read_bit(tker, ri, mi++) & (x >> i) & (x >> j) & 1;
            //assert(mi == n_cols);
            assert(nm == 0);
        }
    }
    */
    for(size_t ri = 0; ri < tker->nrows; ri++)
    {
        printf("%d ", (int)tgt);
        for(size_t ci = 0; ci < tker->ncols; ci++)
            printf("%d", (int)mzd_read_bit(tker, ri, ci));
        printf("\n");
    }
    mzd_free(tker);
}
int main()
{
    for(size_t i = 0; i < 256; i++)
        process(i);
}
```

`hax.cpp` 如下：

```c++
#include <array>
#include <vector>
#include <random>
#include <bitset>
#include <m4ri/m4ri.h>
uint8_t func(uint64_t x)
{
    x *= 5;
    x = (x << 7) | (x >> (64 - 7));
    x *= 9;
    return x >> 56;
}
constexpr size_t N_MONO = 1 + 256 + 256 * 255 / 2;
using deg2_rel = std::bitset<1 + 256 + 256 * 255 / 2>;
using deg2_rel64 = std::bitset<1 + 64 + 64 * 63 / 2>;
using lin_rel = std::bitset<256>;
struct sym_u64
{
    lin_rel st[64] {};
    sym_u64& operator^=(const sym_u64& rhs)
    {
        for(size_t i = 0; i < 64; i++)
            st[i] ^= rhs.st[i];
        return *this;
    }
    sym_u64 operator^(const sym_u64& rhs) const
    {
        sym_u64 ret = *this;
        ret ^= rhs;
        return ret;
    }
    sym_u64 operator<<(int by) const
    {
        sym_u64 ret {};
        for(size_t i = 0; i < 64 - by; i++)
            ret.st[i + by] = st[i];
        return ret;
    }
    sym_u64 operator>>(int by) const
    {
        sym_u64 ret {};
        for(size_t i = 0; i < 64 - by; i++)
            ret.st[i] = st[i + by];
        return ret;
    }
    sym_u64 rotl(int by) const
    {
        sym_u64 ret {};
        for(size_t i = 0; i < 64; i++)
            ret.st[(i + by)%64] = st[i];
        return ret;
    }
};
struct sym_xs256
{
    sym_u64 s0, s1, s2, s3;
    sym_xs256()
    {
        for(size_t i = 0; i < 64; i++)
        {
            s0.st[i][i] = true;
            s1.st[i][i+64] = true;
            s2.st[i][i+128] = true;
            s3.st[i][i+192] = true;
        }
    }
    sym_u64 step()
    {
        sym_u64 res_s1 = s1;
        sym_u64 t = s1 << 17;
        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;
        s2 ^= t;
        s3 = s3.rotl(45);
        return res_s1;
    }
};
std::array<std::vector<deg2_rel64>, 256> krels;
deg2_rel to_deg2(lin_rel lhs)
{
    deg2_rel ret {};
    for(size_t i = 0; i < 256; i++)
        ret[i+1] = lhs[i]; // 0 is the constant term
    return ret;
}
deg2_rel mul(lin_rel lhs, lin_rel rhs)
{
    deg2_rel ret {}; // compute the product coefficients directly
    size_t mi = 1;
    for(size_t i = 0; i < 256; i++)
    {
        ret[mi] = ret[mi] ^ (lhs[i] & rhs[i]);
        mi++;
    }
    for(size_t i = 0; i < 256; i++)
    for(size_t j = 0; j < i; j++)
    {
        ret[mi] = ret[mi] ^ (lhs[i] & rhs[j]);
        ret[mi] = ret[mi] ^ (lhs[j] & rhs[i]);
        mi++;
    }
    return ret;
}
int main()
{
    FILE* f = fopen("list_rels", "r");
    while(true)
    {
        char buf[4096];
        int res = 0;
        int ok = fscanf(f, "%d%s", &res, buf);
        if(ok < 2)
            break;
        deg2_rel64 rel {};
        for(size_t i = 0; i < rel.size(); i++)
            rel[i] = buf[i] - '0';
        krels[res].push_back(std::move(rel));
    }
    fclose(f);
    sym_xs256 rng {};
    // we're targeting the state before the flag is encrypted so skip some bytes now
    f = fopen("out_bin", "rb");
    constexpr int FLAG_LEN = 41;
    uint8_t encflag[FLAG_LEN];
    for(size_t i = 0; i < 41; i++)
    {
        encflag[i] = fgetc(f);
        rng.step();
    }
    std::vector<deg2_rel> all_rels;
    for(size_t i = 0; i < 2000; i++)
    {
        fprintf(stderr, "i=%d\n", i);
        uint8_t outb = fgetc(f);
        sym_u64 s1 = rng.step();
        for(const deg2_rel64& big_rel : krels[outb])
        {
            deg2_rel res {};
            size_t mi = 1;
            if(big_rel[0])
                res[0] = res[0] ^ 1;
            for(size_t i = 0; i < 64; i++)
            {
                if(big_rel[mi])
                    res ^= to_deg2(s1.st[i]);
                mi++;
            }
            for(size_t i = 0; i < 64; i++)
            for(size_t j = 0; j < i; j++)
            {
                if(big_rel[mi])
                    res ^= mul(s1.st[i], s1.st[j]);
                mi++;
            }
            all_rels.push_back(res);
        }
    }
    fclose(f);
    fprintf(stderr, "%zu\n", all_rels.size());
    mzd_t *A = mzd_init(all_rels.size(), N_MONO);
    for(size_t i = 0; i < all_rels.size(); i++)
    {
        for(size_t j = 0; j < N_MONO; j++)
            mzd_write_bit(A, i, j, all_rels[i][j]);
    }
    // we solve this system by linearization
    fprintf(stderr, "starting solve\n");
    fprintf(stderr, "mat dim: %zu rows, %zu cols\n", A->nrows, A->ncols);
    mzd_t* ker = mzd_kernel_left_pluq(A, 0);
    mzd_t* tker = mzd_transpose(nullptr, ker);
    fprintf(stderr, "tker dim: %zu rows, %zu cols\n", tker->nrows, tker->ncols);
    mzd_free(A);
    mzd_free(ker);
    assert(tker->nrows == 1); // only 1 solution
    sym_xs256 rng2 {};
    lin_rel ist; // the initial state. dot product with symbolic output equals concrete output
    for(size_t j = 0; j < 256; j++)
        ist[j] = mzd_read_bit(tker, 0, j + 1);
    for(size_t i = 0; i < FLAG_LEN; i++)
    {
        sym_u64 s1 = rng2.step();
        uint64_t x = 0;
        for(size_t j = 0; j < 64; j++)
            x |= uint64_t((s1.st[j] & ist).count() % 2) << j;
        uint8_t outb = func(x);
        printf("%c", encflag[i] ^ outb);
    }
    printf("\n");
}
```

## 我的想法

首先我感觉这玩意挺抽象的，思路先不谈，光那俩 cpp 除了春哥我不知道还有谁能这么点时间内造出来。
试着用 sage 写了下 `gen_rels.cpp`，直接慢了几十倍，好吧还是 C++ 厉害。（那之前的 MT19937 的题我是不是可以用 C++ 重写来着，又给自己挖个坑）

先看看 `gen_rels.cpp` 干了些啥：对每一个 0-255 的 target，找到 20000 个能让 `f(x) == target` 的 x，然后把这些 x 的每一位都当作一个变量，构造一个矩阵，然后求这个矩阵的核，这个核就是 `f(x) == target` 的所有关系的矩阵表示。这里的矩阵是 20000*2081 的，然后用 M4RI 求核。
最终求出的每个向量与其对应 s1 expand 出的二次向量的内积都为 0。

再看 `hax.cpp`，~~疲软了，有空再来补坑。~~
时隔大半年回来补了（

这里面真是一堆语法可真是把没学过 C++ 的我搞得一头雾水。
直接用最憨的方法，一个个看。

函数 `func`： 将 `s1` 转成 `result`
`deg2_rel` 是一个 32897 维的向量，`deg2_rel64` 是 2081 维的向量，`lin_rel` 是 256 维的向量。
struct `sym_u64`： 64 维的向量，每一个分量都是一个 `lin_rel`，那么这应该算一个 64*256 的矩阵，并定义其异或、左移、右移、循环左移操作。
struct `sym_xs256`： 4 个 `sym_u64` 类型的 `s1 s2 s3 s4`，并定义了 `step` 操作，这里不是很懂，按理说这四个状态向量都是 64 位的。
定义了一个 `krels`，包含 256 个 `std::vector<deg2_rel64>` 类型的元素。每一个 `std::vector<deg2_rel64>` 可以包含任意数量的 `deg2_rel64` 对象。

现在来看 `main` 函数：
把 `list_rels` 文件中的内容读入到 `krels` 中。
创建一个 `sym_xs256` 类的实例 `rng`，然后读进 encflag，每读一个字符更新一次 `rng` 的状态。
对每一个泄露的字节，找到所有 `krels` 中对应的 `big_rels`，然后对每一个 `big_rels`，新建一个类型为 `deg2_rel` 的 `res`，常数项（0 号位）和 `big_rels` 取等，1-64 号位是 $(b_1, b_2, \cdots, b_{64})\cdot(s_1,s_2,\cdots,s_{64})^T$，左边的 $b$ 即为 `big_rels` 的 1-64 号位，右边是 s1 的 64*256 矩阵。后面没看懂。

最后汇总到的一个 `all_rels`，求核得到的矩阵只有一个 32897 维的向量，剥出 1-256 号位得到 `ist`。

整个看下来就是迷迷糊糊的。

黑化了。

I recently contacted the author of this challenge for assistance and was surprised by his quick response. Despite it being 00:30 when I reached out, he replied by 02:30. Given his username, I assumed he was in Russia, but his response time led me to question whether his work and rest schedule is typical or if he is not currently in Russia.

The key to understanding the classes `sym_u64` and `sym_xs256` lies in the fact that the four states can be represented as a 256-bit vector. This representation forms a linear system that omits the non-linear scrambler `f(x)`. Thus, the state transition function can be expressed as a matrix, and the `step` function simply performs matrix multiplication. More specifically, the n-th state is obtained by multiplying the transition matrix $T$ by the initial state $n$ times.

The construction of `res` can be explained as follows:

First, it's important to note that `s1` is a 64x256 matrix which, when multiplied by `ist`, yields the current real state of `s1`. Each `s1[i]` is a 256-dimensional vector; its dot product with `ist` determines the i-th bit of the current `s1`.
For each `res` in `all_rels`, `res` is computed by multiplying the `big_rel` (a 2081-dimensional vector) by a 2081x256 matrix, which is derived from `s1`.

## 参考

<https://github.com/colgreen/Redzen/blob/main/Redzen/Random/Xoshiro256StarStarRandom.cs>
<https://github.com/C4T-BuT-S4D/bricsctf-2023-stage1/blob/master/tasks/crp/random/README.md>
