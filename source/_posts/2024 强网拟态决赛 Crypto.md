---
title: 2024 强网拟态决赛 Crypto
date: 2024-11-29 21:03:00
tags: [CTF, Crypto]
categories: 题解
---

特种兵 CTF 南京站，就打了两道密码，写一下
<!--more-->

## notiv

### 题目

`task.py` 如下：

```python
# !/usr/bin/env python
from hashlib import sha256
import socketserver
import os
import sys
import random
import signal
import string
from hashlib import sha256
from mypad import *

from Crypto.Cipher import AES
from random import *
from Crypto.Util.number import *


class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline:
                msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b'> '):
        self.send(prompt, newline=False)
        return self._recvall()

    def close(self):
        self.request.close()

    def proof_of_work(self):
        seed(os.urandom(8))
        proof = ''.join(
            [choice(string.ascii_letters+string.digits) for _ in range(20)])
        _hexdigest = sha256(proof.encode()).hexdigest()
        self.send(f"[+] sha256(XXXX+{proof[4:]}) == {_hexdigest}".encode())
        x = self.recv(prompt=b'[+] Plz tell me XXXX: ')
        if len(x) != 4 or sha256(x+proof[4:].encode()).hexdigest() != _hexdigest:
            return False
        return True

    def handle(self):
        try:
            if not self.proof_of_work():
                self.send(b"try again!")
                self.close()
                exit()

            #signal.alarm(120)
            count = 0
            for _ in range(50):
                seed(os.urandom(8))
                key = pad_x923(b"")
                chal = hex(getrandbits(64*3))[2:].zfill(16*3)

                for i in range(200):
                    iv = long_to_bytes(getrandbits(128)).rjust(16, b"\00")
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    test = self.recv(b":> ").decode()
                    tb = bytes.fromhex(test)
                    ret = cipher.encrypt(pad_x923(tb))
                    if len(ret) > 16:
                        self.send(b"forbid")
                        continue
                    self.send((iv+ret).hex().encode())

                s = self.recv(b">> ").decode()
                iv = bytes.fromhex(s[:32])
                ans = bytes.fromhex(s[32:])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                att = cipher.decrypt(ans)
                att = unpad_x923(att)
                if att == chal.encode():
                    count += 1
            self.send(b"you got %d score" % count)
            if count >= 20:
                f=open("./flag","rb")
                FLAG=f.read()
                f.close()
                self.send(b"cong!your flag is "+FLAG)
            else:
                self.send(b"sorry,plz try again")
        except:
            self.send(b"something wrong! plz try again!")
            self.close()


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 12345
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
```

`mypad.py` 如下：

```python
from Crypto.Random import get_random_bytes

pad_x923=lambda x,block_size=16:x+get_random_bytes((block_size-(len(x)%block_size)-1))+bytes([(block_size-len(x)%block_size)])
unpad_x923=lambda x,block_size=16:x[:-((x[-1]-1)%block_size)-1]
```

### 分析

主要考点就是一个 CBC mode 的 AES，如何利用多次随机 IV 的 oracle 搞出一个能解密出 chal 的 IV 和 ciphertext，因为 key 是无法还原的。
首先肯定是要逆出 chal，典型的 MT19937，注意到 `getrandbits(128)` 其实就是 4 个 `getrandbits(32)` 拼接出来的，题目给出的 IV 完全是满足 19968 bits 还原的条件，但是注意到 seed 是 8 字节随机数，也就是说不需要 624 个 `getrandbits(32)` 就可以还原出 seed，我用的是 272 个，也就是 68 个 `getrandbits(128)`，实际更少应该也行，但是不会有很明显的优化了，吧。
然后很奇怪的一个点是 chal 虽然是 `getrandbits(64*3)`，按理说是 24 字节，但是出题人 hex 了一下，变成了 48 字节，这是一个蛮迷惑的操作，当时我找工作人员跟他确认的时候，他说这是故意做的字符空间压缩，实际上我觉得没鸟蛋区别，因为碰撞的过程中是完全随机的。

然后就是构造的部分，这个 AES 的 blocksize 是 16 字节，那么就是要构造 4 个 block，因为 pad 会多补一个 block，这个 block 的末字节的低 4 位是 0。
注意到输入只给你输入 15 字节，所以构造的 block 只有前 15 字节是可控的，最后一个字节就要爆破，不做任何优化的情况下，第一个 block 可以直接改向量控制最后一个字节，第二、三个 block 都要爆 1/256，第四个 block 只需要爆 1/16，因为只需要令最后一个字节的低 4 位是 0。

### exp

基本是稳定 30 分的，题目说的什么一次不行再来两次的，根本不需要好吧（除非你大非酋非到没边了

```python
from pwn import *
from Crypto.Util.number import *
from tqdm import trange, tqdm
from Crypto.Random import get_random_bytes
from seedrecovery import MT19937RecoverSeed
import random
import itertools as its
import string
from hashlib import sha256

pad_x923=lambda x,block_size=16:x+get_random_bytes((block_size-(len(x)%block_size)-1))+bytes([(block_size-len(x)%block_size)])
unpad_x923=lambda x,block_size=16:x[:-((x[-1]-1)%block_size)-1]

r = remote('127.0.0.1', 12345)

# context.log_level = 'debug'

def proof_of_work(suffix, hash, prelen=4):
    table = string.ascii_letters+string.digits
    r = its.product(table, repeat=prelen)
    for i in tqdm(r):
        i = ''.join(i)
        str = i + suffix
        str_256 = sha256(str.encode()).hexdigest()
        if str_256 == hash:
            return i
    raise Exception('Not Found')

def iv2num(iv: bytes):
    nums = []
    iv = bytes_to_long(iv)
    for _ in range(4):
        nums.append(iv % 2**32)
        iv >>= 32
    return nums

def oracle(p: bytes):
    r.sendlineafter(b":> ", p)
    res = r.recvline().strip().decode()
    iv = bytes.fromhex(res)[:16]
    ciphertext = bytes.fromhex(res)[16:]
    return iv, ciphertext

prefix = r.recvuntil(b')').decode()[-17:-1]
h = r.recvline().decode()[4:-1]
r.recvuntil(b'[+] Plz tell me XXXX: ')
r.sendline(proof_of_work(prefix, h, 4).encode())

win = 0
for _ in trange(50):
    data = []

    for _ in range(68):
        iv, _ = oracle(b'00')
        data += iv2num(iv)

    assert len(data) == 272
    recover = MT19937RecoverSeed([0]*6 + data, 8)
    seed = recover.get_seed()
    random.seed(seed)

    # chal = long_to_bytes(random.getrandbits(64*3))
    chal = hex(random.getrandbits(64*3))[2:].zfill(16*3).encode()
    iv_list = [long_to_bytes(random.getrandbits(128)).rjust(16, b"\00") for _ in range(200)]

    TRY_TABLE_LEN = 16
    ivs = []
    for _ in range(TRY_TABLE_LEN):
        iv, enc = oracle(chal[:15].hex().encode())
        ivs.append((200, iv, enc))

    # now find the iv and enc
    for i in range(TRY_TABLE_LEN):
        _, iv, enc = ivs[i]
        for j in range(68 + TRY_TABLE_LEN, 180):
            iv2 = iv_list[j]
            check = list(iv2)[-1] ^ list(enc)[-1] ^ 1 == chal[31]
            if check:
                # success(j)
                ivs[i] = (j, iv, enc)
                break
    ivs = [i for i in ivs if i[0] != 200]
    ivs.sort(key=lambda x: x[0])
    # info(ivs)
    info("%d possble ivs found" % len(ivs))

    count = 68 + TRY_TABLE_LEN
    while True:
        iv3_found = False
        if count > 199:
            warn("GG")
            break

        result = next((iv for iv in ivs if iv[0] == count), None)
        if result is None:
            oracle(b'00')
            count += 1
            continue
        else:
            iv, enc = result[1], result[2]

        iv2 = iv_list[count]
        payload = bytes_to_long(chal[16:32]) ^ bytes_to_long(iv2) ^ bytes_to_long(enc)
        payload = long_to_bytes(payload)
        payload = payload[:15]

        iv2_true, enc2 = oracle(payload.hex().encode())
        assert iv2_true == iv2, (iv2_true, iv2)

        for i in range(count, 190):
            iv3 = iv_list[i]
            check = list(iv3)[-1] ^ list(enc2)[-1] ^ 1 == chal[47]
            if check:
                iv3_found = True
                break

        count += 1
        if iv3_found:
            success("BLOCK1 PASS AT %d" % count)
            break
        else:
            continue
    # info(count)
    while True:
        if count > 199:
            warn("GG")
            enc3 = b'\x00'*16
            break
        iv3 = iv_list[count]
        count += 1
        payload = bytes_to_long(chal[32:48]) ^ bytes_to_long(iv3) ^ bytes_to_long(enc2)
        payload = long_to_bytes(payload)
        payload = payload[:15]

        iv3_true, enc3 = oracle(payload.hex().encode())

        check = list(iv3)[-1] ^ list(enc2)[-1] ^ 1 == chal[47]
        if check:
            success("BLOCK2 PASS AT %d" % count)
            break
        else:
            continue

    while True:
        if count > 199:
            warn("GG")
            enc4 = b'\x00'*16
            break
        iv4 = iv_list[count]
        count += 1
        payload = bytes_to_long(b'\x00') ^ bytes_to_long(iv4) ^ bytes_to_long(enc3)
        payload = long_to_bytes(payload)
        payload = payload[:15]

        iv4_true, enc4 = oracle(payload.hex().encode())

        check = (list(iv4)[-1] ^ list(enc3)[-1] ^ 1) & 0xf == 0
        if check:
            success("BLOCK3 PASS AT %d OHHHHHHHH!!!!!!!" % count)
            win += 1
            break
        else:
            continue

    info("Win times: (%d / 20)" % win)
    for _ in range(200 - count):
        oracle(b'00')
    iv = list(iv)
    iv[-1] = iv[-1] ^ 1 ^ chal[15]
    iv = bytes(iv)
    payload2 = iv + enc + enc2 + enc3 + enc4
    r.sendlineafter(b">> ", payload2.hex().encode())
r.interactive()
```
