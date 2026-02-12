---
title: 2025 CISCN & CCB - Crypto
date: 2024-12-17 18:56:00
tags: [CTF, Crypto]
categories: 题解
---

四个一血，那就是四血，四血就是没血，没血就是菜鸡，所以我是菜鸡
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
因为 $x_1$ 和 $x_2$ 比较小，所以可以直接爆出来，然后 $x_2h_1 - x_1h_2$ 就能把 $p$ 消掉，只剩下 $q$ 的倍数，跟 $n$ 做一下 GCD 就分解出来了。

Part2 给了
$$
h = (514p - 114q)^{n - p - q} \pmod n
$$

注意到 $n - p - q = \varphi(n) - 1$，所以 $h$ 就是 $514p - 114q$ 的逆元，这个时候代入 $q = n/p$ 就能化成一个关于 $p$ 的一元二次方程，用通解解出来就行了。
好像看到某支大神队伍用结式搞，有点杀鸡用牛刀了。

## fffffhash

题目如下：

```python
import os
from Crypto.Util.number import *
def giaogiao(hex_string):
    base_num = 0x6c62272e07bb014262b821756295c58d
    x = 0x0000000001000000000000000000013b
    MOD = 2**128
    for i in hex_string:
        base_num = (base_num * x) & (MOD - 1) 
        base_num ^= i
    return base_num


giao=201431453607244229943761366749810895688

print("1geiwoligiaogiao")
hex_string = int(input(),16)
s = long_to_bytes(hex_string)

if giaogiao(s) == giao:
    print(os.getenv('FLAG'))
else:
    print("error")
```

原
[DownUnderCTF2023 fnv](https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/crypto/fnv/solve/solution_joseph_LLL.sage)
有空再来分析
今年的国赛也出了一道 FNV，但是是明确是 7 个字节的，所以可以直接 MITM，也就是中间相遇搞出来。

## LWEWL

```python
from Crypto.Util.number import *
from random import randint
from secret import flag

assert flag.startswith(b'flag{') and flag.endswith(b'}')
flag = flag[5:-1]
flag1 = flag[:len(flag)//2]
flag2 = flag[len(flag)//2:]

class LWE:
    def __init__(self, lwe_dim, lwe_num_samples, lwe_plaintext_modulus, lwe_ciphertext_modulus, rlwe_dim, rlwe_modulus):
        self.lwe_dim = lwe_dim
        self.lwe_num_samples = lwe_num_samples
        self.lwe_plaintext_modulus = lwe_plaintext_modulus
        self.lwe_ciphertext_modulus = lwe_ciphertext_modulus
        self.lwe_secret_key = self.distribution(0, self.lwe_ciphertext_modulus - 1, self.lwe_dim)
        self.rlwe_dim = rlwe_dim
        self.rlwe_modulus = rlwe_modulus

    def distribution(self, lbound, rbound, dim):
        return [randint(lbound, rbound) for _ in range(dim)]

    def lwe_encrypt(self, message):
        a = self.distribution(0, lwe_ciphertext_modulus - 1, self.lwe_dim)
        e = self.distribution(-15, 15, 1)[0]
        return a, sum([a[i] * self.lwe_secret_key[i] for i in range(self.lwe_dim)]) + message + e * lwe_plaintext_modulus

    def lwe_keygen(self):
        A = []
        B = []
        for _ in range(self.lwe_num_samples):
            sample = self.lwe_encrypt(0)
            A.append(sample[0])
            B.append(sample[1])
        return A, B

    def encrypt(self, message, lwe_pubkey1, lwe_pubkey2):
        const = vector(ZZ, self.distribution(-1, 1, self.lwe_num_samples))
        e = self.distribution(-15, 15, 1)[0]
        return const * matrix(GF(lwe_ciphertext_modulus), lwe_pubkey1), const * vector(GF(lwe_ciphertext_modulus), lwe_pubkey2) + message + e * lwe_plaintext_modulus

    def rlwe_sample(self, flag):
        P.<x> = PolynomialRing(Zmod(self.rlwe_modulus))

        while True:
            monomials = [x^i for i in range(self.rlwe_dim + 1)]
            c = self.distribution(0, self.rlwe_modulus - 1, self.rlwe_dim) + [1]
            f = sum([c[i] * monomials[i] for i in range(self.rlwe_dim + 1)])
            PR = P.quo(f)
            if f.is_irreducible():
                break
        a = self.distribution(0, self.rlwe_modulus - 1, self.rlwe_dim)
        e = self.distribution(-5, 5, self.rlwe_dim)
        s = [flag[i] for i in range(len(flag))]
        b = PR(a) * PR(s) + PR(e)
        return a, b, f, self.rlwe_modulus

lwe_dimension = 2**9
lwe_num_samples = 2**9 + 2**6 + 2**5 + 2**2
lwe_plaintext_modulus = next_prime(256)
lwe_ciphertext_modulus = next_prime(1048576)
rlwe_dim = 64
rlwe_modulus = getPrime(128)

lwe = LWE(lwe_dimension, lwe_num_samples, lwe_plaintext_modulus, lwe_ciphertext_modulus, rlwe_dim, rlwe_modulus)
lwe_pubkey1, lwe_pubkey2 = lwe.lwe_keygen()
lwe_public_key = [lwe_pubkey1, lwe_pubkey2]
lwe_cipher1 = []
lwe_cipher2 = []
for flag_char in flag1:
    tmp1, tmp2 = lwe.encrypt(flag_char, lwe_pubkey1, lwe_pubkey2)
    lwe_cipher1.append(tmp1)
    lwe_cipher2.append(tmp2)

lwe_ciphertext = [lwe_cipher1, lwe_cipher2]
save(lwe_public_key, "lwe_public_key")
save(lwe_ciphertext, "lwe_ciphertext")

rlwe_ciphertext = lwe.rlwe_sample(flag2)
save(rlwe_ciphertext, "rlwe_ciphertext")
```

双原合一
Dicectf2023 membrane
NSSCTF Round18 New Year Ring3
也是有空再来分析

## babypqc

题目如下：

```python
import ctypes
from random import getrandbits
import signal
import socketserver
from sympy import nextprime
import numpy as np  
from Crypto.Util.number import *
import ast


def ll_to_polylist(l):
    return list(map(list, list(l)))

class Dilithium:
    def __init__(self):
        self.dilithium_lib = ctypes.CDLL("./dilithium/libpqcrystals_dilithium2_ref.so")
        self.pk_buf = ctypes.c_buffer(1312)
        self.sk_buf = ctypes.c_buffer(2560)
        self.Q = 8380417
        self.N = 256
        self.dilithium_lib.pqcrystals_dilithium2_ref_keypair(self.pk_buf, self.sk_buf)

    def sign_message(self, message: bytes) -> bytes:
        SIGNLEN = 2420
        MLEN = len(message)
        sm_buf = ctypes.create_string_buffer(SIGNLEN + MLEN)
        m_buf = ctypes.create_string_buffer(message)
        smlen_buf = ctypes.c_size_t()
        self.dilithium_lib.pqcrystals_dilithium2_ref(sm_buf, ctypes.byref(smlen_buf), m_buf, MLEN, self.sk_buf)
        return sm_buf.raw[:smlen_buf.value]

    def verify_sign(self, message: bytes, signature: bytes) -> bool:
        msg_buf = ctypes.create_string_buffer(len(signature))
        msg_len = ctypes.c_size_t()
        sm_buf = ctypes.create_string_buffer(signature)
        result = self.dilithium_lib.pqcrystals_dilithium2_ref_open(msg_buf, ctypes.byref(msg_len), sm_buf, len(signature), self.pk_buf)
        return result == 0 and message == msg_buf.raw[:msg_len.value]


class Task(socketserver.BaseRequestHandler):
    def __init__(self, *args, **kargs):
        super().__init__(*args, **kargs)
    

    def timeout_handler(self, signum, frame):
        raise TimeoutError
    

    def dosend(self, msg):
        try:
            self.request.sendall(msg.encode('latin-1') + b'\n')
        except:
            pass


    def recvline(self, msg = None):
        if msg:
            self.request.sendall(msg.encode('latin-1'))
        try:
            data = b""
            while True:
                chunk = self.request.recv(1)
                if not chunk:
                    break
                data += chunk
                if chunk == b'\n':
                    break
        except:
            pass

        line = data.strip().decode()
        return line

        
    def generate_prime(self, BITS):
        a = getrandbits(BITS)
        b = a << 282
        c = nextprime(b)
        return c
    

    def generate_coefs(self, BITS, LEN):
        return [getrandbits(BITS) for _ in range(LEN)]
    

    def get_sk(self):
        poly_t = ctypes.c_int32 * self.dilithium.N
        polyvec_t = poly_t * 4
        rho = ctypes.c_buffer(32)
        tr = ctypes.c_buffer(64)
        key = ctypes.c_buffer(32)
        t0 = polyvec_t()
        s1 = polyvec_t()
        s2 = polyvec_t()
        self.dilithium.dilithium_lib.pqcrystals_dilithium2_ref_unpack_sk(rho, tr, key, t0, s1, s2, self.dilithium.sk_buf)
        return ll_to_polylist(s1), ll_to_polylist(s2)


    def handle(self):
        signal.signal(signal.SIGALRM, self.timeout_handler)
        signal.alarm(40)
        self.dosend("welcome to my crypto system!")
        delta = 1184
        beta = 256
        tau = 704
        self.m = getrandbits(beta)
        self.dilithium = Dilithium()

        p = self.generate_prime(delta)
        q = self.generate_prime(delta)
        N = [p * q]
        ROUND = 25
        for _ in range(ROUND):
            d = getrandbits(704)
            N.append((p + d) * (q + d))
        self.dosend("N = " + str(N))
        s1, s2 = self.get_sk()
        s1 = np.array([i for j in s1 for i in j])
        s2 = np.array([i for j in s2 for i in j])
        
        H = []
        for i in range(ROUND * ROUND):
            tmp = np.array(self.generate_coefs(32, 1024))
            H.append(int(tmp.dot(s1) % self.dilithium.Q))
            tmp = np.array(self.generate_coefs(32, 1024))
            H.append(int(tmp.dot(s2) % self.dilithium.Q))

        self.dosend("this is your hint!")
        self.dosend("H = " + str(H))
        self.dosend("another gift: you can choose one message to sign")
        m = int(self.recvline("m: "))
        signature = self.dilithium.sign_message(long_to_bytes(m))
        assert self.dilithium.verify_sign(long_to_bytes(m), signature)
        self.dosend("this is your signature")
        self.dosend("sinature = " + signature.hex())
        num = self.generate_coefs(4, 1)[0]
        self.dosend("you need to give me some signatures in hex format!")
        signatures = ast.literal_eval(self.recvline("signatures: "))
        assert len(list(set(signatures))) == len(signatures)
        answers = sum([self.dilithium.verify_sign(long_to_bytes(self.m), bytes.fromhex(sinature.zfill(len(signature) + len(signature)%2))) for sinature in signatures])
        if answers == num:
            self.dosend("congrats! you got the flag!")
            with open("flag.txt") as f:
                self.dosend(f.read())
        else:
            self.dosend("sorry, you failed!")
            exit()
        


class ThreadedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 13337
    server = ThreadedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
```

### 极简非预期

第一次输入 `0`
第二次输入 `[]`
你就有 1/16 的概率拿到 flag

这题居然只有两个解，一看代码全被吓跑了

### 正经解法

首先是打一个 MT19937，题目给的随机数加起来刚好是 19968 bit 的，所以需要利用 N （一个 list）把 p q 分解出来，这部分可以用 AGCD 搞出来。
搞到这 m 就还原出来了，塞给他签名，就拿到了一个正确的签名，再交回去，answers 就是 1，num 是 0-15 的随机数，赌他随出 1 就行。
也就是这时候我发现随出 0 也行，也就是上面的极简非预期解法。。。无语了
打出 MT19937 后 tmp 就全知道了，$s_1$ 由于是只有 512 个非零元素，所以可以直接 `solve_right` 解出来，但是 $s_2$ 是满的，应该要用格搞一搞。

作业没写完，有空再来补。
