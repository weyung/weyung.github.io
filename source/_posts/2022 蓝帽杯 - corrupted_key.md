---
title: 2022 蓝帽杯 - corrupted_key
date: 2022-07-16 13:08:00
tags: [CTF, 密码学]
categories: 题解
---

很有意思的一道题，涉及私钥文件的结构。
<!--more-->
********************************

## 题目

给了一个 `priv.pem`

```plain
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDXFSUGqpzsBeUzXWtG9UkUB8MZn9UQkfH2Aw03YrngP0nJ3NwH
UFTgzBSLl0tBhUvZO07haiqHbuYgBegO+Aa3qjtksb+bH6dz41PQzbn/l4Pd1fXm
dJmtEPNh6TjQC4KmpMQqBTXF52cheY6GtFzUuNA7DX51wr6HZqHoQ73GQQIDAQAB








yQvOzxy6szWFheigQdGxAkEA4wFss2CcHWQ8FnQ5w7k4uIH0I38khg07HLhaYm1c
zUcmlk4PgnDWxN+ev+vMU45O5eGntzaO3lHsaukX9461mA==
-----END RSA PRIVATE KEY-----
```

和一个加密的脚本

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from secret import flag

key = RSA.generate(1024)
open("flag.enc",'wb').write(PKCS1_OAEP.new(key.publickey()).encrypt(flag))
open('priv.pem','wb').write(key.exportKey('PEM'))
```

然后就是 `flag.enc`

## 分析

### 数理部分

题目名为 **corrupted_key** ，意为残损的私钥文件，既然是残损的，那么剩下的部分就是解题的关键了。
通过查看 `Crypto.PublicKey.RSA` 的源码，发现私钥文件的结构是：

```plain
0 （注意！！！！）
n
e
p
q
d mod (p-1)
d mod (q-1)
(inverse of q) mod p
```

完整来说是

```plain
RSAPrivateKey ::= SEQUENCE {
version Version,
modulus INTEGER, -- n
publicExponent INTEGER, -- e
privateExponent INTEGER, -- d
prime1 INTEGER, -- p
prime2 INTEGER, -- q
exponent1 INTEGER, -- d mod (p-1)
exponent2 INTEGER, -- d mod (q-1)
coefficient INTEGER, -- (inverse of q) mod p
otherPrimeInfos OtherPrimeInfos OPTIONAL
}
```

一通操作后发现可以拿到 $n$,$e$,CRT 系数（即 $q^{-1}\mod p$ ）和 $d_q$ 低位，至于怎么拿到的等下再说，这里可以构造等式如下：
$$
    t = q^{-1} \pmod p \\\\
    tq-1 = 0 \pmod p \\\\
    tq^2 - q = 0 \pmod n
$$
然后
$$
    ed_q = 1 \pmod{q-1} \\\\
    ed_q - 1 = k(q - 1) \\\\
    f = (dq_h + dq_l)e - 1 + k = kq
$$
代入得
$$
    tf^2 - kf = 0 \pmod n
$$
显然 $k$ 和 $e$ 数量级是相当的， $dq_h$ 的未知高位有512-120=392位，就可以通过 coppersmith 爆破 $k$ 。

### 参数提取

然后就是有意思的部分了，如何从残损的私钥文件中提取参数呢？
对着源码一顿调试了几个钟（太菜了呜呜），发现是先将各个参数塞进一个首位为 0 的数组，然后各个参数前面补上长度，后面 `long_to_bytes` 转换成 bytes ，最后拼接起来。
我的提取脚本如下：

```python
from binascii import a2b_base64
from Crypto.Util.asn1 import DerInteger
from Crypto.Util.number import *
pem = '''-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDXFSUGqpzsBeUzXWtG9UkUB8MZn9UQkfH2Aw03YrngP0nJ3NwH
UFTgzBSLl0tBhUvZO07haiqHbuYgBegO+Aa3qjtksb+bH6dz41PQzbn/l4Pd1fXm
dJmtEPNh6TjQC4KmpMQqBTXF52cheY6GtFzUuNA7DX51wr6HZqHoQ73GQQIDAQAB

yQvOzxy6szWFheigQdGxAkEA4wFss2CcHWQ8FnQ5w7k4uIH0I38khg07HLhaYm1c
zUcmlk4PgnDWxN+ev+vMU45O5eGntzaO3lHsaukX9461mA==
-----END RSA PRIVATE KEY-----'''

pemlist = pem.split('\n')
decode_b64 = b''
for i in pemlist[1:-1]:
    decode_b64+=a2b_base64(i)
decode_b64 = decode_b64[4:] # 丢弃前4个字节

der_int = DerInteger()

# 提取n
n = decode_b64[3:135]
der_int.decode(n)
print('[+] n =',n:=der_int.value)

# 提取e
e = decode_b64[135:140]
der_int.decode(e)
print('[+] e =',e:=der_int.value)

# 提取CRT系数
for len in range(1,300):
    try:
        q_inv_p = decode_b64[-len:]
        der_int.decode(q_inv_p)
        print('[+] q_inv_p =',q_inv_p:=der_int.value)
    except:
        len+=1
    else:
        # print(len)    # 67
        break
# print(q_inv_p.bit_length())   # 512

# 提取dp低位
dp_l = decode_b64[-82:-67]
# print(dp_l)
print('[+] dp_l =',bytes_to_long(dp_l))
```

可以看到我一开始直接把前 4 个字节丢了，然后在新 List 里用库函数解析 3 - 134 号位的数据，这部分就是属于 $n$ 的，然而实际上 `bytes_to_long` 解析 7 - 134 号位的数据得到的也是 $n$ ，那么问题来了， 3 - 6 号位这 4 个字节里放了啥？

以下是新List：

```plain
\x02\x01\x00\x02\x81\x81\x00\xd7\x15%\x06\xaa\x9c...
```

这里涉及一个**ASN.1**（Abstract Syntax Notation dot one，即抽象记法1）的问题，简单来说就是将数据编码成 3 个部分：**标志域、长度域、值域**
标志域中，约定 02 表示整数
长度域稍微复杂些，记录的是值域的长度，分为定长和不定长两种情况
定长时，若值域长度不超过 127 ，则用**短格式**表示，也就是直接用 16 进制表示，比如长度为 31 就是 0x1F ，即 0001 1111 ；若长度超过 127 ，则用**长格式**表示，首字节的首位置 1 表示长格式，后面7位则表示后面再跟多少个表示长度的字节，比如 1000 0001 表示后面 1 个字节表示长度，后面的长度也是直接用 16 进制表示。
现在可以看到新 List 中， 0 号位为 02 表示整数， 1 号位 01 表示长度为 1 ， 2 号位 00 表示数据为 0 ，这就是上面提到的私钥文件结构中的那个 0 。
再继续分析， 3 号位 02 表示数据为整数， 4 号位中的首比特为1表示使用长格式，后面 7 个比特为 000 0001 意为数据长度用 1 个字节表示，没错就是后面紧跟的 5 号位，表示数据长度为 0x81 ，转换成 10 进制就是 129 ，试了一下 6 - 134 号位用 `bytes_to_long` 解析出来的数据，也是 $n$
那么现在你应该也可以尝试写出 $e$ 的编码：

```plain
\x02\x03\x01\x00\x01
```

细心的你还发现我开头扔了 4 个字节，猜猜是啥呢？
答案是整个私钥文件编码后作为值域前面补的标签域和长度域，最前面再补一个 0 ，也就是

```plain
0\x82\x02^
```

后两个字节 `bytes_to_long` 解码后是 606 ，恰为后面跟的完整数据的长度

> 后来偶然间发现竟然有类似的题目（）
[0CTF 2016 Quals equation](https://ctftime.org/task/2127)

## 参考

<https://mp.weixin.qq.com/s/A9OmgHAmGLJPEL4cQBU8zQ>
<https://www.likecs.com/show-40060.html>
