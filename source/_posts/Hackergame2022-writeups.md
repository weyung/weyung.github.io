---
title: Hackergame 2022 writeups
date: 2022-10-30 17:26:00
tags: CTF
categories: 题解
---

好玩，爆赞！
<!--more-->
## Summary

不知不觉，离上一年Hackergame都一年了 ~~（有点像废话）~~，作为我CTF的启蒙赛， Hackergame 2021 拿分最多的其实还是靠 web ，如今我却出乎意料地成为了队里的密码手。
今年已经不像上年那么有空，前面的搜索题都没空做。总体来说，虽然做不出来，但好歹也能将大部分题目阅读一遍了。~~（有进步，但不多）~~
没好意思填学校的组，直接在公开组注册，最终得分 2850 ，总排名 145 ，也就只有 math 榜上能看见我了。
GZTime 还是如同上年一样直线上分，但意想不到的是mcfx也被一个不明来路的直线上分的老六偷了榜一。
这里记录一下解出的题的题解，对解不出但尝试过的，也作一些记录，多少从中学到了一些东西。
最近要期中考，断断续续更这里吧。

********************************

## 签到

点开网页，发现是一个手写签名，四个框内，依次要在2秒，1秒，0.1秒，0.0秒内分别写下`2022`才能通过。
首先直接靠手速必然是不行的，因为第四个框最多只能留下一个点，于是尝试点了个提交，发现顶上的url多了个`?result=????`，果然还是和上年一样的套路，四个问号改成 2022 ，回车，得到 flag 。

## 猫咪问答喵

第一问直接搜就有，第二问没找到，第三问也直接搜，第四问没找，第六问爆破出来的（）
第五问也没找出来，但是找到一个网站叫 [Censys.io](https://search.censys.io/data) ，似乎可以搜索 ssh 的 sha256 指纹查 host ，以及有关一堆乱七八糟的查询，不知道以后能不能用得上。

## 家目录里的秘密

Level1 直接搜目录内文件就有。
Level2 没下 Rclone ，以为要找到那个`rclone.config`文件里的真实域名再ftp进去。。。

## HeiLang

`Ctrl`+`H`，将 ` | ` 全部替换成 `]=a[` 即可。

## Xcaptcha

用 `pyppeteer` 干了，简单粗暴。
代码如下：

```python
import asyncio
from pyppeteer import launch
async def main():
    browser = await launch({
        'executablePath': r'C:\Program Files\Google\Chrome\Application\chrome.exe',
        'headless': False,
        'args': ['--no-sandbox', '--window-size=1366,850']
    })
    page = await browser.newPage()
    await page.setViewport({'width':1366,'height':768})
    await page.goto('http://202.38.93.111:10047/?token=<your_token>') 
    await page.click('.img-fluid')
    captcha1 = await page.querySelectorEval('label[for="captcha1"]', 'node => node.innerText')
    captcha2 = await page.querySelectorEval('label[for="captcha2"]', 'node => node.innerText')
    captcha3 = await page.querySelectorEval('label[for="captcha3"]', 'node => node.innerText')
    res1=eval(captcha1[:-5])
    res2=eval(captcha2[:-5])
    res3=eval(captcha3[:-5])
    await page.type('#captcha1', str(res1))
    await page.type('#captcha2', str(res2))
    await page.type('#captcha3', str(res3))
    await page.click('#submit')
    
    flag = await page.querySelectorEval('body > div > p:nth-child(4)', 'node => node.innerText')
    print(flag)
    await browser.close()
asyncio.get_event_loop().run_until_complete(main())
```

## 旅行照片2.0

Level1 直接用在线网站就能看，但 EXIF 版本信息显示是 `0231` ，结合题目提示，改成 `2.31` 就行。
Level2 一开始谷歌和百度识图都出不来，然后发现识图的结果都是夕阳，于是把图片**截去夕阳部分**再谷歌识图，就能得到拍摄角度几乎一样但是白天的日本千叶市美滨区的海洋球场，然后找机场就找头疼了，放弃。
在做复变函数的时候无意间发现 wolfram 可以通过看到飞机的地点和时间直接查询航班，但是是会员功能。

## 猜数字（未解出）

写了个脚本暴猜一晚上没出，果然运气还是太差了。
正解是 `NaN` ，不提。
这里贴一下我爆破的脚本，供君一乐：

```python
import requests as r
import re

url = 'http://202.38.93.111:18000/state'
cookie = '<your_cookie>'
auth = '<your_auth>'

def guess(num):
    data = f'<state><guess>{num}</guess></state>'
    r.post(url, headers={'Cookie': cookie, 'authorization': auth}, data=data)
    
def check():
    res = r.get(url, headers={'Cookie': cookie, 'authorization': auth})
    resp = re.findall(r'<guess less="(\w+)" more="(\w+)">(.*?)</guess>', res.text)
    if not resp:
        return ('true', 'true', '0')
    return resp[0]

def crack(n):
    guess(str(n/1000000))
    less, more, num = check()
    # print(less, more, num)
    left = 0
    right = 1000000
    times = 1
    while less != 'true' or more != 'true':
        times += 1
        if less == 'true':
            left = float(num)*1000000
        elif more == 'true':
            right = float(num)*1000000
        else:
            break
        num = (left + right) // 2
        tmp = num
        guess(str(num/1000000))
        less, more, num = check()
        # print(less, more, num)
    return times, tmp

if __name__ == '__main__':
    l = [500000]
    while True:
        # n = 500000*(len(l)+1) - sum(l)
        # n = min(n, 1000000)
        # n = max(n, 0)
        n = 1000000 - sum(l)//len(l)
        times, num = crack(n)
        l.append(int(num))
        print(times, n, num, sum(l)//len(l))
        if times == 1:
            break
    print('done')
```

## LaTeX机器人

Level1 我的解法：

```tex
\newread\myread \openin\myread=/flag1 \read\myread to \fileline \fileline{}
```

Level2 打不通，但找到一个可以取消所有转义的函数 ~~（但我忘了是什么）~~。

## 安全的在线测评

我 Level1 的解法，但似乎预期是用编译器读？

```c
#include <stdio.h>

int main() {
    // read 2 lines from file
    char buf[400];
    scanf("%s", buf);

    FILE *fp = fopen("./data/static.out", "r");
    fgets(buf, 400, fp);
    printf("%s", buf);
    fgets(buf, 400, fp);
    printf("%s", buf);
    fclose(fp);
    return 0;
}
```

## Flag自动机

第一回正式打逆向，首先题目是一个恶作剧程序，就是不给点 `狠心夺取` 按钮，于是拖进 `IDA` 看到有 `rand` 函数，不难联想到按钮的新位置是通过这个函数产生的，于是再查看 `rand` 函数的调用，发现只有两处——分别是按钮的 X 坐标和 Y 坐标。然后我的解法是把汇编上把位置 patch 成 `0` ，这样按钮就只刷新在左上角了。点击按钮后，弹出一个提示框——`获取flag失败！您不是本机的“超级管理员”！` ，于是再次在 `IDA` 找到一个判断，若该变量不等于 `114514` ，则弹出失败的提示框，这里在汇编把 `jz` patch 成 `jnz` 就行。最后成功获取 flag 。

## 杯窗鹅影

Level1 我的解法如下：

```c
#include <stdio.h>

// read file in /flag1

int main(void) {
    FILE *fp = fopen("/flag1", "r");
    if (fp == NULL) {
        printf("open file failed");
    }
    char buf[0x100];
    fgets(buf, 0x100, fp);
    printf("%s", buf);
    return 0;
}
```

## 蒙特卡洛轮盘赌

测试得出 `clock()` 的大小在 1000 左右，那么假定时间基本同步的情况下爆破 1000 次左右即可出结果。
编译开 `-O3` 的情况下目测大约每秒 20 次，大约在 50s 内可出结果。
代码如下：

```python
import subprocess
import time
from pwn import *
import os

# compile the c program
os.system('gcc -o setseed setseed.c -O3')

def seedtores(seed):
    p = subprocess.run(
            ['./setseed', str(seed)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
    return (p.stdout.decode()).split()

def crack(pi2, t):
    p1, p2 = pi2
    while True:
        res = seedtores(t)
        print(res[0],res[1], res[2], end='\r')
        if res[1] == p1 and res[2] == p2:
            return t, res
        else:
            t += 1

now = int(time.time())

print(now)

r = remote('202.38.93.111', 10091)

token = b'<your_token>'
r.sendlineafter(b'token:', token)
r.sendlineafter('请输入你的猜测（如 3.14159，输入后回车）：'.encode(), b'0')
r.recvuntil('正确答案是：'.encode())
p1 = r.recvline().decode().strip()
r.sendlineafter('请输入你的猜测（如 3.14159，输入后回车）：'.encode(), b'0')
r.recvuntil('正确答案是：'.encode())
p2 = r.recvline().decode().strip()

info('p1: %s, p2: %s', p1, p2)
t, guess = crack((p1, p2), now)
success('guess: %s', guess)

r.sendlineafter('请输入你的猜测（如 3.14159，输入后回车）：'.encode(), guess[3].encode())
r.sendlineafter('请输入你的猜测（如 3.14159，输入后回车）：'.encode(), guess[4].encode())
r.sendlineafter('请输入你的猜测（如 3.14159，输入后回车）：'.encode(), guess[5].encode())
print(r.recvlines(3))
```

其中 `setseed.c` 代码如下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

double rand01()
{
    return (double)rand() / RAND_MAX;
}

// let main receive a seed
int main(int argc, char *argv[])
{
    // disable buffering
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    unsigned int seed = 1666610168+946;
    seed = atoi(argv[1]);
    printf("%u\n",seed);
    srand(seed-1);
    int games = 5;
    int win = 0;
    int lose = 0;
    char target[20];
    char guess[2000];
    for (int i = games; i > 0; i--) {
        int M = 0;
        int N = 400000;
        for (int j = 0; j < N; j++) {
            double x = rand01();
            double y = rand01();
            if (x*x + y*y < 1) M++;
        }
        double pi = (double)M / N * 4;
        sprintf(target, "%1.5f", pi);
        printf("%1.5f\n", pi);
    }
    return 0;
}
```

## 置换魔群

打通了，还行。
置换群的概念题目已经说得很清楚了，这里不再赘述。
Level1 是生成一个置换群 $A_n$ ，并给出 $x^e$ 和 $e=66537$ ，求群 $A_n$ 的元素 $x$ 。
那么这就很类似 RSA 了，首先 RSA 的解密原理是，对于模 $n$ 群，对其中的**任意元素** $x$ ，都有 $x^{\varphi(n)}\equiv1\mod n$ ，这里的$\varphi(n)$称为**群的阶**。所以 $m^{ed}\equiv m^{k\varphi(n)+1}\equiv (m^{\varphi})^km\equiv m\mod n$ 。（srds，这竟然是我在做这道题的时候推公式想明白的）
那么回到这个题就很简单了，只需求出 $A_n$ 的阶，然后取 $e$ 模 $A_n$ 阶的逆元就能得到解密指数 $d$ 了。
题目给了简陋的求群的阶的函数，但速度比较慢，用 sagemath 实现了一下，快了很多。
关键代码如下：

```python
def solve(n, c, e=65537):
    S = SymmetricGroup(n)
    d = pow(e, -1, S.order())
    res = S(c) ** int(d)
    return str(list(res.tuple()))   # 这里应该有更优雅的写法
```

Level2 同样生成一个置换群 $A_n$ ，给出一个元素 $g$ 和 $g^y$ ，要求 $y$ 。
那么这就是一个离散对数问题了，用 sagemath 的 `discrete_log` 函数就能解决。
当然如果你和我一样不知道 sagemath 的置换群用的哪个函数，可以使用万能的 copilot 直接先敲一行注释，然后回车按`tab` 。
关键代码如下：（只有两行，乐）

```python
def solve(g, y, n):
    S = SymmetricGroup(n)
    return discrete_log(S(y), S(g))
```

Level3 同样是离散对数问题，允许输入两个元素 $g_1$ 和 $g_2$ ，然后给出 $g_1^m$ 和 $g_2^m$ ，要求 $m$ 。
上面提到了**群的阶**，这里引入**元素的阶**的概念：比如模 $5$ 的群中，群的阶为 $\varphi(5)=4$ ，也就是说 $1^4\equiv2^4\equiv3^4\equiv4^4\mod 5$ ，但是我们发现， $1^1 \mod1$ 就已经是 $1$ 了， $4^2\mod 5$ 也一样不需要达到 $4$ 次方就到 $1$ ，这里我们称**最小的** $k$ 使元素 $x$ 满足 $x^k\equiv1\mod n$ 为**元素 $x$ 的阶**，也就是说如上的例子中 $1$ 的阶为 $1$ ， $4$ 的阶为 $2$ 。
现在回到题目，我们发现难点在于要求的 $m$ 是比较大的，记 $g_1$ 和 $g_2$ 的阶分别为 $a$ 和 $b$ ，容易知道我们求离散对数得到的只是 $m_1\equiv m\mod a$ 和 $m_2\equiv m\mod b$ ，由中国剩余定理可知最后求出的 $m'\equiv m\mod \mathrm{lcm}(a,b)$ ，也就是说，我们构造的 $g_1$ 和 $g_2$ 的阶的**最小公倍数需要足够大**才能得到 $m$ 。

然后不难搜得求置换群元素的阶最大的问题可以转化成求一组数的和不超过 $n$ ，如果使这组数的最小公倍数最大的问题。显然这组数应该是互质的，但**这并不意味着这组数要全为质数**！比如 $n=7$ 时，我们可以得到 $3\times4$ 是最大的， $3$ 和 $4$ 互质，但 $4$ 不是质数。如此我们可以手推几个，然后在数列网站 OEIS 上搜索得到数列[A000793](https://oeis.org/A000793)，关于这个数列的介绍为 `Landau's function g(n): largest order of permutation of n elements. Equivalently, largest LCM of partitions of n.`
显然这正是我们要找的，于是复制下面给出的代码就可以生成 $g_1$ 了，而对于 $g_2$ ，我的做法是拿到 $g_2$ 中最大数后面的素数列填充进去，若不能继续填充且空间还有剩余，则使最后两个素数**尽可能大且尽可能相近**。
最后我的蹩脚算法得出来的界大部分比题目的界要大，有小部分小 $1/10$ 左右，基本上都能大过 $m$ 。

贴一下完整的垃圾代码：

```python
from pwn import *
from sage.all import *
from sympy import primerange, prevprime

p = remote("202.38.93 .111", 10114)
# context.log_level = "debug"
token = <your_token>
p.sendlineafter(b"token: ", token.encode())
p.sendlineafter(b"> your choice: ", b"3")

def n2perm(l):
    ll = []
    i = 1
    for x in l:
        ll.append(tuple(range(i, i+x)))
        i += x
    return ll

def aupton(N):  # compute terms a(0)..a(N)
    V = [1 for _ in range(N+1)]
    for i in primerange(2, N+1):
        for j in range(N, i-1, -1):
            hi = V[j]
            pp = i
            while pp <= j:
                hi = max((pp if j == pp else V[j-pp]*pp), hi)
                pp *= i
            V[j] = hi
    return V

def get_fac(n):
    prod = data[n - 1]
    f = factor(prod)
    f_ = str(f).split('*')
    fl = []
    for i in f_:
        if '^' in i:
            fl.append(eval(i.replace('^', '**')))
        else:
            fl.append(int(i))
    return fl

def get_fac2(n, fl1_prod):
    fl2 = []
    i = 2
    while sum(fl2) < n:
        if gcd(i, fl1_prod) == 1:
            fl2.append(i)
        i += 1
    if sum(fl2) > n:
        fl2.pop()
        fl2.pop()
        fl2.append(prevprime(n - sum(fl2)))
    return fl2

def get_n2l(n):
    l1 = get_fac(n)
    l2 = get_fac2(n, prod(l1))
    return n2perm(l1), n2perm(l2)

def get_n():
    p.recvuntil(b'[+] DH public key: n = ')
    n = int(p.recvline()[:-1].decode())
    return n

def get_bound():
    p.recvuntil(b'[+] The upper bound for my private key is ')
    bound = int(p.recvline()[:-1].decode())
    return bound

def get_pub(g):
    p.sendlineafter(b'(a list): ',g.encode())
    p.recvuntil(b' : ')
    y = eval(p.recvline()[:-1].decode())
    return y

for i in range(15):
    n = get_n()
    bound = get_bound()
    info(f"    n = {n}")
    info(f"bound = {bound}")
    S = SymmetricGroup(n)
    data = aupton(2000)
    g,g_ = get_n2l(n)
    g1, g2 = S(g), S(g_)
    opt = lcm(g1.order(), g2.order())
    info(f"  opt = {opt}")
    if opt < bound:
        warning("opt < bound")
    pub1 = get_pub(str(list(g1.tuple())))
    pub2 = get_pub(str(list(g2.tuple())))
    pub1, pub2 = S(pub1), S(pub2)
    m1, m2 = discrete_log(pub1,g1), discrete_log(pub2,g2)
    # success(f"m1 = {m1}\nm2 = {m2}")
    m = crt([m1,m2],[g1.order(),g2.order()])
    success(f"    m = {m}")
    p.sendlineafter(b'> your answer: ', str(m).encode())
    res = p.recvline().decode()
    assert res == 'Good job\n', res

print(p.recvline().decode())
```

## 矩阵之困（未解出）

开赛做完签到后看的第一题，结果最后也成为本场比赛最难的 1 解题（表面看起来是 2 解，但其实两个号都是 mcfx），不得不说我眼光真好（）
查到三向量内积可表示成 $a^TBc$ ，其中 $B$ 的对角线为 $b$ ，但似乎没什么用。
用z3梭了几天出不来，放弃。

## 片上系统（未解出）

发现 pulseview 还挺有意思。

## 量子藏宝图

挺有意思的，一直只研究后量子密码学，却没看过量子密码，正好补充知识。

## 企鹅拼盘

Level1 手试即可，结果为 `1000` 。

## 火眼金睛的小E

Level1 直接装个 bindiff 人工比对，但是正确率不太高，需要多试几次，有时甚至 bindiff 连函数都没检测出来。。。
