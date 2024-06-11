---
title: NTRUEncrypt
date: 2022-04-11 00:26:00
tags: [数学,格,抽象代数,Crypto]
categories: 学习
---
NTRUEncrypt 公钥加密系统
<!--more-->
## 简介

这里基本摘自维基百科，少少枯燥，可以自行选择略读。

NTRUEncrypt 是一个公钥加密系统，它的安全性基于这样一个问题的困难性：在一个截断多项式环（这个翻译怪怪的）中**将一个给定的多项式分解成两个系数非常小的多项式的商**。
由于加密与解密都只涉及简单的多项式乘法，故相比于其他的加密系统， NTRUEncrypt 的**效率会更高**。
具体来说， NTRU 的操作基于截断多项式环中的对象 ${\displaystyle \ R=\mathbb {Z} [X]/(X^{N}-1)}$ 中的**卷积乘法**，并且环上的所有多项式的系数和次数都为不大于 $N-1$ 的整数。
实际上， NTRU 是一个参数化系统，每个系统由三个整数指定 $(N,p,q)$ ，其中 $N$ 代表截断环上的所有多项式的最高次为 $N-1$ ， $p$ 和 $q$ 分别代表一个小模数和一个大模数。其中 $N$ 为素数， $q$ 大于 $p$ ，且 $p$ 与 $q$ 互质。由这三个参数生成四个多项式 $\mathcal {L}_f,\mathcal {L}_g,\mathcal {L}_m \thinspace$ 和 $\mathcal {L}_r$ ，分别为私钥、公钥、消息和干扰数。
********************************
看到这里，我相信懂的人都懂的，不懂的人还不懂（bushi）
下面从宏观和微观两方面详细解释

## 公钥生成

又双叒叕来到了密码学的老 CP —— Alice 和 Bob
![Alice&Bob](https://gimg2.baidu.com/image_search/src=http%3A%2F%2Fauthorize.zhongbi.net%2Fd%2Ffile%2Ftu%2F2018%2F12%2F27%2F0wlyvynx1dv.jpg&refer=http%3A%2F%2Fauthorize.zhongbi.net&app=2002&size=f9999,10000&q=a80&n=0&g=0n&fmt=auto?sec=1652234696&t=c5802c1784650149a8a25e0440448985)

1. Bob 根据选定的 $N,p,q$ 生成最高次为 $N-1$ 的 $f$ 和 $g$ **两个多项式**，并且系数在 $\{-1,0,1\}$ 中选取（可以认为这俩是在模 $X^{N}-1$ 的剩余类中）。 $f$ 还要满足**模 $q$ 和 $p$ 的逆元存在**，如果不满足，那就重新生成。
2. 分别计算 $f$ 模 $p$ 和模 $q$ 的逆元，即 $f_{p}$ 和 $f_{q}$ ，**保留 $f$ , $f_{p}$ 及 $g$ 作为私钥，公钥 $h=pf_{q} \cdot g\ \pmod{q} $ 。**

sagemath 代码如下

```python
def generate_keys():
    ''' 基于提供的参数生成一个公私钥对
        返回 f (私钥)和 F_p (公钥)'''

    # 校验
    if validate_params():
        while True:
            try:
                # 生成两个随机多项式 f 和 g ，并且非零系数小于给定的 d
                f = generate_polynomial(d)
                g = generate_polynomial(d)

                # 假定 q 是 2 的幂，求得 f 模 q 的逆元             
                f_q = invertmodpowerof2(f,q)
                # 同样假定 p 是素数，求得 f 模 p 的逆元
                f_p = invertmodprime(f,p)  
                break
        
            except:
                # 上面如果抛出异常，即逆元不存在，则重新生成
                pass 
    
        # 公钥 h=pf_p*g (mod q)
        public_key = balancedmod(p * convolution(f_q,g),q)

        # 保留 f 和 f_p 作为私钥
        secret_key = f,f_p

        return public_key,secret_key

    else:
        print("Provided params are not correct. q and p should be co-prime, q should be a power of 2 considerably larger than p and p should be prime.")

```

## 加密

Alice 将消息 $m$ 转化成一个系数在 $\{-1,0,1\}$ 之间的多项式（比如转成二进制或三进制，二进制在这里会有些浪费），再随机生成一个系数较小（但不限于 $\{-1,0,1\}$ 中）的多项式 $r$ 作为干扰以掩盖消息。那么加密计算如下：
$$
    e=r \cdot h+m \pmod{q}
$$
举个栗子：
当取 $N=5,p=3,q=32$ 时（呃这里待更新）
$$
    f=-1+X+X^2
$$

```python
def generate_message():
    ''' 随机生成一个系数在{-1,0,1}中的多项式'''

    result = list(randrange(3) - 1 for _ in range(N))
    return Zx(result)
def encrypt(message, public_key):
    ''' 基于提供的公钥加密消息'''

    # 生成一个随机多项式，并且非零系数小于给定的d，作为干扰以掩盖消息   
    r = generate_polynomial(d)

    # 加密：e = r * h + m (mod q)
    # while performing modulo operation, balance coefficients of encrypted_message 
    # for the integers in interval [-q/2, +q/2]
    return balancedmod(convolution(public_key,r) + message,q)
```

## 解密

由于其他人不知道 $r$ ，所以无法直接 $m=e-rh$ ，但 Bob 拿到 $e$ 后，可以计算出
$$
\begin{equation*}
\begin{split}
    a
    & = f \cdot e \pmod{q}\\\\
    & = f \cdot (r \cdot h+m) \pmod{q}\\\\
    & = f \cdot (r \cdot pf_{q} \cdot g+m) \pmod{q}\\\\
    & = pr \cdot g + f \cdot m \pmod{q}
\end{split}
\end{equation*}
$$
关键部分来了，以上都是在模 $q$ 下进行，而这时忽然就变成了模 $p$
$$
b=a=f \cdot m \pmod{p} \\\\
c=f_{p} \cdot b =f_{p} \cdot f \cdot m =m \pmod{p}
$$

```python
def decrypt(encrypted_message, secret_key):
    ''' 基于提供的私钥解密密文'''
    
    # 拿到私钥的两个多项式  
    f,f_p = secret_key
    
    # a = f * e (mod p)
    a = balancedmod(convolution(encrypted_message,f),q)
     
    # c = f_p * a (mod p)
    return balancedmod(convolution(a,f_p),p)
```

## 函数实现

下面从微观上解释一下上面函数的实现：

### 卷积

多项式卷积满足公式
$$
    a(x)*b(x) = c(x) \ with \ c_k = \sum_{i+j=k \pmod} a_i b_{k-i \pmod{N}}
$$
举个栗子：
$$
    f(x)=-1+4x+x^2 \\\\
    g(x)=3-x+5x^2
$$
注意此时多项式和级数类似，采用低次项在先的书写方式
则
$$
    f(x)*g(x) = c(x) \pmod{3}
$$
其中
$$
c_0 = \sum_{i+j=0 \pmod{N}} f_i g_{0-i} = f_0g_0 + f_1g_2 + f_2g_1 = -1 \times 3 + 4 \times 5 + 1 \times (-1) = -3 + 20 + (-1) = 16 \\\\
c_1 = f_0g_1 + f_1g_0 + f_2g_2 = -1 \times (-1) + 4 \times 3 + 1 \times 5 = 1 + 12 + 5 = 18 \\\\
c_2 = f_0g_2 + f_1g_1 + f_2g_0 = -1 \times 5 + 4 \times (-1) + 1 \times 3 = -5 + (-4) + 3 = -6
$$
故
$$
c(x) = 16 + 18x - 6x^2
$$
代码如下：

```python
def convolution(f,g):
    ''' 多项式卷积运算'''
    
    return (f * g) % (x^N-1)
```

### 取模

这里将多项式的每个系数 $f_i$ 拿出来，然后作变换 $g_i=(f_i+q/2)\%q-q/2$ 再塞回去。这样每个系数都在 $[-q/2,q/2]$ 之间，这样可以保证模 $q$ 的运算。
比如取 $q=3$ 时，有以下映射关系：
$$
-3 \rightarrow (-3+1)\%3 -1 = 0 \\\\
-2 \rightarrow (-2+1)\%3 -1 = 1 \\\\
-1 \rightarrow (-1+1)\%3 -1 = -1 \\\\
0 \rightarrow (0+1)\%3-1 = 0 \\\\
1 \rightarrow (1+1)\%3-1 = 1 \\\\
2 \rightarrow (2+1)\%3-1 = -1 \\\\
3 \rightarrow (3+1)\%3-1 = 0
$$
代码如下：

```python
def balancedmod(f,q):
    ''' 多项式取模'''

    g = list(((f[i] + q//2) % q) - q//2 for i in range(N))
    return Zx(g)
```

### 求逆元

这也是我比较疑惑的一部分，一直不知道多项式的逆元具体怎么求，现在也看开了，随便怎么样吧，反正不是我手写（）
这里先变基到 $X^N-1$ 商环然后求逆元再 lift 到整环上，关于原理我至今有点异或，有缘回来补坑吧。
代码如下：

```python
def invertmodprime(f,p):
    ''' 假定 p 为素数,计算一个多项式模 x^N-1 下的逆元再模 p
        返回一个 Zx 上的多项式 h 满足 h 与 f 卷积模 p 为 1
        不存在逆元时会抛出异常'''

    T = Zx.change_ring(Integers(p)).quotient(x^N-1)
    return Zx(lift(1 / T(f)))

def invertmodpowerof2(f,q):
    ''' 假定 q 为 2 的幂，计算一个多项式模 x^N-1 下的逆元再模 q
        返回一个 Zx 上的多项式 h 满足 h 与 f 卷积模 q 为 1
        不存在逆元时会抛出异常'''

    assert q.is_power_of(2)     # 断言 q 是 2 的幂
    h = invertmodprime(f,2)     # 首先求 f 模 2 的逆元
    while True:
        r = balancedmod(convolution(h,f),q)         # 计算 r = h * f (mod q)
        if r == 1: return h                         # 若 h * f = 1 (mod q)，则返回 h 即为所求逆元
        h = balancedmod(convolution(h,2 - r),q)     # 否则，h = h * (2 - r) (mod q)
```

## 攻击

格约化攻击是一种非常著名的针对 NTRUEncrypt 的攻击，类似于 RSA 分解质因数。
当选取的 $N$ 较小时，可以构造维度较低的格分解公钥 $h$ 。

### 例题 SCTF2020-Lattice

```python
from base64 import b16encode

Zx.<x> = ZZ[]
n = 109 
q = 2048
p = 3
Df = 9
Dg = 10
Dr = 11

def mul(f,g):
    return (f * g) % (x^n-1)

def bal_mod(f,q):
    g = list(((f[i] + q//2) % q) - q//2 for i in range(n))
    return Zx(g)

def random_poly(d):
    assert d <= n
    result = n*[0]
    for j in range(d):
        while True:
            r = randrange(n)
            if not result[r]: break
        result[r] = 1-2*randrange(2)
    return Zx(result)

def inv_mod_prime(f,p):
    T = Zx.change_ring(Integers(p)).quotient(x^n-1)
    return Zx(lift(1 / T(f)))

def inv_mod_powerof2(f,q):
    assert q.is_power_of(2)
    g = inv_mod_prime(f,2)
    while True:
        r = bal_mod(mul(g,f),q)
        if r == 1: return g
        g = bal_mod(mul(g,2 - r),q)

def keygen():
    f = random_poly(Df)
    while True:
        try:
            fp = inv_mod_prime(f,p)
            fq = inv_mod_powerof2(f,q)
            break
        except:
            f = random_poly(Df)
    g = random_poly(Dg)
    h = bal_mod(p * mul(fq,g),q)
    pub_key = h
    pri_key = [f,fp]
    return pub_key,pri_key

def encrypt(m,h):
    r = random_poly(Dr)
    e = bal_mod(mul(h,r) + m,q)
    return e

if __name__ == '__main__':
    pub_key,pri_key = keygen()
    flag=b'SCTF{***********}'[5:-1]
    m = Zx(list(bin(int(b16encode(flag), 16))[2:]))
    print(m)
    e = encrypt(m,pub_key)
    print('pub_key=')
    print(pub_key)
    print('e=')
    print(e)
# pub_key=
# 510*x^108 - 840*x^107 - 926*x^106 - 717*x^105 - 374*x^104 - 986*x^103 + 488*x^102 + 119*x^101 - 247*x^100 + 34*x^99 + 751*x^98 - 44*x^97 - 257*x^96 - 749*x^95 + 648*x^94 - 280*x^93 - 585*x^92 - 347*x^91 + 357*x^90 - 451*x^89 - 15*x^88 + 638*x^87 - 624*x^86 - 458*x^85 + 216*x^84 + 36*x^83 - 199*x^82 - 655*x^81 + 258*x^80 + 845*x^79 + 490*x^78 - 272*x^77 + 279*x^76 + 101*x^75 - 580*x^74 - 461*x^73 - 614*x^72 - 171*x^71 - 1012*x^70 + 71*x^69 - 579*x^68 + 290*x^67 + 597*x^66 + 841*x^65 + 35*x^64 - 545*x^63 + 575*x^62 - 665*x^61 + 304*x^60 - 900*x^59 + 428*x^58 - 992*x^57 - 241*x^56 + 953*x^55 - 784*x^54 - 730*x^53 - 317*x^52 + 108*x^51 + 180*x^50 - 881*x^49 - 943*x^48 + 413*x^47 - 898*x^46 + 453*x^45 - 407*x^44 + 153*x^43 - 932*x^42 + 262*x^41 + 874*x^40 - 7*x^39 - 364*x^38 + 98*x^37 - 130*x^36 + 942*x^35 - 845*x^34 - 890*x^33 + 558*x^32 - 791*x^31 - 654*x^30 - 733*x^29 - 171*x^28 - 182*x^27 + 644*x^26 - 18*x^25 + 776*x^24 + 845*x^23 - 675*x^22 - 741*x^21 - 352*x^20 - 143*x^19 - 351*x^18 - 158*x^17 + 671*x^16 + 609*x^15 - 34*x^14 + 811*x^13 - 674*x^12 + 595*x^11 - 1005*x^10 + 855*x^9 + 831*x^8 + 768*x^7 + 133*x^6 - 436*x^5 + 1016*x^4 + 403*x^3 + 904*x^2 + 874*x + 248
# e=
# -453*x^108 - 304*x^107 - 380*x^106 - 7*x^105 - 657*x^104 - 988*x^103 + 219*x^102 - 167*x^101 - 473*x^100 + 63*x^99 - 60*x^98 + 1014*x^97 - 874*x^96 - 846*x^95 + 604*x^94 - 649*x^93 + 18*x^92 - 458*x^91 + 689*x^90 + 80*x^89 - 439*x^88 + 968*x^87 - 834*x^86 - 967*x^85 - 784*x^84 + 496*x^83 - 883*x^82 + 971*x^81 - 242*x^80 + 956*x^79 - 832*x^78 - 587*x^77 + 525*x^76 + 87*x^75 + 464*x^74 + 661*x^73 - 36*x^72 - 14*x^71 + 940*x^70 - 16*x^69 - 277*x^68 + 899*x^67 - 390*x^66 + 441*x^65 + 246*x^64 + 267*x^63 - 395*x^62 + 185*x^61 + 221*x^60 + 466*x^59 + 249*x^58 + 813*x^57 + 116*x^56 - 100*x^55 + 109*x^54 + 579*x^53 + 151*x^52 + 194*x^51 + 364*x^50 - 413*x^49 + 614*x^48 + 367*x^47 + 758*x^46 + 460*x^45 + 162*x^44 + 837*x^43 + 903*x^42 + 896*x^41 - 747*x^40 + 410*x^39 - 928*x^38 - 230*x^37 + 465*x^36 - 496*x^35 - 568*x^34 + 30*x^33 - 158*x^32 + 687*x^31 - 284*x^30 + 794*x^29 - 606*x^28 + 705*x^27 - 37*x^26 + 926*x^25 - 602*x^24 - 442*x^23 - 523*x^22 - 260*x^21 + 530*x^20 - 796*x^19 + 443*x^18 + 902*x^17 - 210*x^16 + 926*x^15 + 785*x^14 + 440*x^13 - 572*x^12 - 268*x^11 - 217*x^10 + 26*x^9 + 866*x^8 + 19*x^7 + 778*x^6 + 923*x^5 - 197*x^4 - 446*x^3 - 202*x^2 - 353*x - 852
```

显然函数和上面的基本一样，只是名称相应地缩短了一下。
攻击方法是构造如下的一个格，然后进行规约
$$
\left(
\begin{array}{cccc|cccc}
\lambda & 0 & \cdots & 0 & h_0 & h_1 & \cdots & h_{N-1} \\\\
0 & \lambda & \cdots & 0 & h_{N-1} & h_0 & \cdots & 0 \\\\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \ddots & 0 \\\\
0 & 0 & \cdots & \lambda & h_1 & h_2 & \cdots & h_0 \\\\ \hline
0 & 0 & \cdots & 0 & q & 0 & \cdots & 0 \\\\
0 & 0 & \cdots & 0 & 0 & q & \cdots & 0 \\\\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \ddots & \vdots \\\\
0 & 0 & \cdots & 0 & 0 & 0 & \cdots & q
\end{array}
\right)
$$
具体可以参考这篇 Paper: <https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.578.5423&rep=rep1&type=pdf>
取 $\lambda=1$ ，规约后最短向量即为 $[f\enspace g]$ ，然后就可以计算私钥解密了。
exp 如下：

```python
from Crypto.Util.number import *
import time
start = time.time()
Zx.<x> = ZZ[]
n = 109 
q = 2048
p = 3
Df = 9
Dg = 10
Dr = 11
h=510*x^108 - 840*x^107 - 926*x^106 - 717*x^105 - 374*x^104 - 986*x^103 + 488*x^102 + 119*x^101 - 247*x^100 + 34*x^99 + 751*x^98 - 44*x^97 - 257*x^96 - 749*x^95 + 648*x^94 - 280*x^93 - 585*x^92 - 347*x^91 + 357*x^90 - 451*x^89 - 15*x^88 + 638*x^87 - 624*x^86 - 458*x^85 + 216*x^84 + 36*x^83 - 199*x^82 - 655*x^81 + 258*x^80 + 845*x^79 + 490*x^78 - 272*x^77 + 279*x^76 + 101*x^75 - 580*x^74 - 461*x^73 - 614*x^72 - 171*x^71 - 1012*x^70 + 71*x^69 - 579*x^68 + 290*x^67 + 597*x^66 + 841*x^65 + 35*x^64 - 545*x^63 + 575*x^62 - 665*x^61 + 304*x^60 - 900*x^59 + 428*x^58 - 992*x^57 - 241*x^56 + 953*x^55 - 784*x^54 - 730*x^53 - 317*x^52 + 108*x^51 + 180*x^50 - 881*x^49 - 943*x^48 + 413*x^47 - 898*x^46 + 453*x^45 - 407*x^44 + 153*x^43 - 932*x^42 + 262*x^41 + 874*x^40 - 7*x^39 - 364*x^38 + 98*x^37 - 130*x^36 + 942*x^35 - 845*x^34 - 890*x^33 + 558*x^32 - 791*x^31 - 654*x^30 - 733*x^29 - 171*x^28 - 182*x^27 + 644*x^26 - 18*x^25 + 776*x^24 + 845*x^23 - 675*x^22 - 741*x^21 - 352*x^20 - 143*x^19 - 351*x^18 - 158*x^17 + 671*x^16 + 609*x^15 - 34*x^14 + 811*x^13 - 674*x^12 + 595*x^11 - 1005*x^10 + 855*x^9 + 831*x^8 + 768*x^7 + 133*x^6 - 436*x^5 + 1016*x^4 + 403*x^3 + 904*x^2 + 874*x + 248
e=-453*x^108 - 304*x^107 - 380*x^106 - 7*x^105 - 657*x^104 - 988*x^103 + 219*x^102 - 167*x^101 - 473*x^100 + 63*x^99 - 60*x^98 + 1014*x^97 - 874*x^96 - 846*x^95 + 604*x^94 - 649*x^93 + 18*x^92 - 458*x^91 + 689*x^90 + 80*x^89 - 439*x^88 + 968*x^87 - 834*x^86 - 967*x^85 - 784*x^84 + 496*x^83 - 883*x^82 + 971*x^81 - 242*x^80 + 956*x^79 - 832*x^78 - 587*x^77 + 525*x^76 + 87*x^75 + 464*x^74 + 661*x^73 - 36*x^72 - 14*x^71 + 940*x^70 - 16*x^69 - 277*x^68 + 899*x^67 - 390*x^66 + 441*x^65 + 246*x^64 + 267*x^63 - 395*x^62 + 185*x^61 + 221*x^60 + 466*x^59 + 249*x^58 + 813*x^57 + 116*x^56 - 100*x^55 + 109*x^54 + 579*x^53 + 151*x^52 + 194*x^51 + 364*x^50 - 413*x^49 + 614*x^48 + 367*x^47 + 758*x^46 + 460*x^45 + 162*x^44 + 837*x^43 + 903*x^42 + 896*x^41 - 747*x^40 + 410*x^39 - 928*x^38 - 230*x^37 + 465*x^36 - 496*x^35 - 568*x^34 + 30*x^33 - 158*x^32 + 687*x^31 - 284*x^30 + 794*x^29 - 606*x^28 + 705*x^27 - 37*x^26 + 926*x^25 - 602*x^24 - 442*x^23 - 523*x^22 - 260*x^21 + 530*x^20 - 796*x^19 + 443*x^18 + 902*x^17 - 210*x^16 + 926*x^15 + 785*x^14 + 440*x^13 - 572*x^12 - 268*x^11 - 217*x^10 + 26*x^9 + 866*x^8 + 19*x^7 + 778*x^6 + 923*x^5 - 197*x^4 - 446*x^3 - 202*x^2 - 353*x - 852


def mul(f,g):
    return (f * g) % (x^n-1)
def decrypt(pri_key,e):
    f,fp = pri_key
    a = bal_mod(mul(f,e),q)
    b = bal_mod(mul(a,fp),p)
    pt = ''.join([str(i) for i in b.list()])
    return pt
def bal_mod(f,q):
    g = list(((f[i] + q//2) % q) - q//2 for i in range(n))
    return Zx(g)
def lattice(h,q):
    n = 109
    # h = bal_mod(683*h,q)
    grid = Matrix(ZZ,2*n,2*n)
    cof = h.list()
    offset = 0
    for i in range(2*n):
        for j in range(2*n):
            if i<n:
                if j < n:
                    if i==j:
                        grid[i,j] = 1
                else:
                    grid[i,j] = cof[(j-n-offset)%n]
            elif j>=n and i==j:
                grid[i,j] = q
        offset += 1
    GL = grid.BKZ()
    return GL,grid

def inv_mod_prime(f,p):
    T = Zx.change_ring(Integers(p)).quotient(x^n-1)
    return Zx(lift(1 / T(f)))

GL,grid = lattice(h,q)
SVP = list(GL[0])
f = Zx(SVP[:n])
g = Zx(SVP[-n:])
a = bal_mod(mul(f,e),q)
fp = inv_mod_prime(f,p)
pv = (f,fp)
print(decrypt(pv,e))
flag = int(decrypt(pv,e)+'0'*6,2)
print(flag)
print(long_to_bytes(flag))

end = time.time()
print(end-start)
```

********************************

## 勘误

维基百科中说 $m$ 转化成系数在 $[-p/2,p/2]$ 间多项式，实际应为 $\{-1,0,1\}$ 间。
代码中加密函数原为`return balancedmod(convolution(public_key,p*r) + message,q)`，一般版本中的公钥是没乘 $p$ 的，在加密中才乘，但这里公钥已经乘过 $p$ 了，就可以删去。实测不删去也可正常解密，推测应该是在后面取模时消去了，读者可自行推导。

## 参考

<https://en.wikipedia.org/wiki/NTRUEncrypt>
<https://github.com/joannawetesko/NTRU-cryptosystem/blob/master/NTRU.sage>
<https://blog.csdn.net/sinat_36742186/article/details/83689529>
