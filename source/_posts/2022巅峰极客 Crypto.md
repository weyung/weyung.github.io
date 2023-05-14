---
title: 2022巅峰极客 Crypto
date: 2022-08-18 12:47:00
tags: [CTF, 密码学]
categories: 题解
---

有瓜吃，美滋滋。
<!--more-->

题目质量一般，知识问答还全是搬运今年 ciscn 的。
然后三个队友都没啥空，就我一个做了两道密码，排 88 名，对我这个菜鸡来说也还行吧。

## point-power

```python
from Crypto.Util.number import *
from gmpy2 import *
from random import *
from secrets import flag

assert len(flag)==42
p=getPrime(600)
a=bytes_to_long(flag)
b=randrange(2,p-1)
E=EllipticCurve(GF(p),[a,b])
G=E.random_element()

x1,y1,_=G
G=2*G
x2,y2,_=G

print(f"p = {p}")
print(f"b = {b}")
print(f"x1 = {x1}")
print(f"x2 = {x2}")
'''
p = 3660057339895840489386133099442699911046732928957592389841707990239494988668972633881890332850396642253648817739844121432749159024098337289268574006090698602263783482687565322890623
b = 1515231655397326550194746635613443276271228200149130229724363232017068662367771757907474495021697632810542820366098372870766155947779533427141016826904160784021630942035315049381147
x1 = 2157670468952062330453195482606118809236127827872293893648601570707609637499023981195730090033076249237356704253400517059411180554022652893726903447990650895219926989469443306189740
x2 = 1991876990606943816638852425122739062927245775025232944491452039354255349384430261036766896859410449488871048192397922549895939187691682643754284061389348874990018070631239671589727
'''
```

这题完全是现学现卖，之前只听说过椭圆曲线，然后就跑去学抽代忘记回来了。。。
首先查到椭圆曲线的加法（两点相同的情形）：
$$
x_2=m^2-2x_1\ (mod\ p) \ with \ m=\frac{3x_1^2+a}{2y_1}
$$
又在Sagemath文档查到曲线定义 $y_1^2=x_1^3+ax_1+b$ ，就能联立出一个一元二次方程， exp 如下：

```python
p = 3660057339895840489386133099442699911046732928957592389841707990239494988668972633881890332850396642253648817739844121432749159024098337289268574006090698602263783482687565322890623
b = 1515231655397326550194746635613443276271228200149130229724363232017068662367771757907474495021697632810542820366098372870766155947779533427141016826904160784021630942035315049381147
x1 = 2157670468952062330453195482606118809236127827872293893648601570707609637499023981195730090033076249237356704253400517059411180554022652893726903447990650895219926989469443306189740
x2 = 1991876990606943816638852425122739062927245775025232944491452039354255349384430261036766896859410449488871048192397922549895939187691682643754284061389348874990018070631239671589727

K = GF(p)
n=(K(x2+2*x1)).sqrt()
P.<x>= PolynomialRing(K)
A=1
B=6*x1**2-4*n**2*x1
C=-(4*n**2*x1**3+4*n**2*b-9*x1**4)
f=A*x**2+B*x+C
roots=f.roots()
print(roots)
flag=roots[1][0]
from Crypto.Util.number import *
print(long_to_bytes(int(flag)))
```

## strange curve

```python
from Crypto.Util.number import *
from gmpy2 import *
from secrets import flag
import random

def add(P,Q):
    (x1,y1)=P
    (x2,y2)=Q


    x3=(x1+x2)*(1+y1*y2)*invert((1+x1*x2)*(1-y1*y2),p)%p
    y3=(y1+y2)*(1+x1*x2)*invert((1-x1*x2)*(1+y1*y2),p)%p

    return (x3,y3)

def mul(e,P):
    Q=(0,0)
    e=e%p
    while e:
        if e&1:
            Q=add(Q,P)
        P=add(P,P)
        e>>=1
    return Q

def Legendre(a,p):
    return (pow((a%p+p)%p,(p-1)//2,p))%p

def get_ts(p):
    p=p-1
    count=0
    while p%2==0:
        count+=1
        p=p//2
    return count,p

def get_nonre(p):
    a=random.randint(1,p)
    while Legendre(a,p)==1:
        a=random.randint(1,p)
    return a

def amm2(a,p):
    t,s=get_ts(p)
    ta=pow(get_nonre(p),s,p)
    tb=pow(a,s,p)
    h=1
    for i in range(1,t):
        d=pow(tb,2**t-1-i,p)
        if d==1:
            k=0
        else:
            k=1
        tb=(tb*pow(ta,2*k,p))%p
        h=(h*pow(ta,k,p))%p
        ta=pow(ta,2,p)
    return h*pow(a,(s+1)//2,p)%p  

def solve(a,b,c,p):
    tmpa=1
    tmpb=b*inverse(a,p)%p
    tmpc=c*inverse(a,p)%p
    assert Legendre(tmpb**2*inverse(4,p)-tmpc,p)==1
    res1=(amm2(tmpb**2*inverse(4,p)-tmpc,p)-tmpb*inverse(2,p))%p
    res2=(-amm2(tmpb**2*inverse(4,p)-tmpc,p)-tmpb*inverse(2,p))%p
    return (res1,res2)

def lift(x,a,b,p):
    tmp=b*(x**2-1)*inverse(a*x,p)%p
    return solve(1,-tmp,-1,p)[0]

p=9410547699903726871336507117271550134683191140146415131394654141737636910570480327296351841515571767317596027931492843621727002889086193529096531342265353
a=54733430689690725746438325219044741824500093621550218736194675295708808435509
b=75237024593957256761258687646797952793573177095902495908321724558796076392871
x=bytes_to_long(flag)

while True:
    try:
        y=lift(x,a,b,p)
        break
    except:
        x+=1
        continue

assert a*x*(y**2-1)%p==b*y*(x**2-1)%p

P=(x,y)
e=65537

eP=mul(e,P)
print(f"P = {P}")
print(f"eP = {eP}")
'''
P = (56006392793427940134514899557008545913996191831278248640996846111183757392968770895731003245209281149, 5533217632352976155681815016236825302418119286774481415122941272968513081846849158651480192550482691343283818244963282636939305751909505213138032238524899)
eP = (mpz(8694229840573103722999959579565187489450818138005222030156495740841851804943200684116883831426548909867463656993852596745698999492932194245562062558787005), mpz(9279986963919197374405152604360936066932975197577643570458423456304679111057526702737279809805694360981565554506626018364382736924914907001214909905449002))
'''
```

这题真的是蚌不住，刚放出来解出数就蹭蹭往上涨，还有点怀疑人生，然后仔细观察题目，一看上面，什么玩意，再看下面，什么玩意。。。
直接拿第一个数 `long_to_bytes` ，得到flag。

## Learning with fault

```python
from Crypto.Util.number import *
from gmpy2 import *
from secrets import flag
import os

class RSA():
    def __init__(self,p,q,e):
        self.p=p
        self.q=q
        self.e=e
        self.phi=(p-1)*(q-1)
        self.d=invert(self.e,self.phi)
        self.dp=self.d%(p-1)
        self.dq=self.d%(q-1)
        self.n=p*q
        self.N=getPrime(512)*getPrime(512)

    def sign(self,message):
        m=bytes_to_long(message)
        sig_p=pow(m,self.dp,self.p)
        sig_q=pow(m,self.dq,self.q)
        alpha=q*invert(q,p)
        beta=p*invert(p,q)
        return long_to_bytes((alpha*sig_p+beta*sig_q)%self.n)

    def corrupt_sign(self,message):
        m=bytes_to_long(message)
        sig_p=pow(m,self.dp,self.p)
        sig_q=pow(m,self.dq,self.q)
        alpha=q*invert(q,p)
        beta=p*invert(p,q)
        return long_to_bytes((alpha*sig_p+beta*sig_q)%self.N)

    def verify(self,message,sign):
        return long_to_bytes(pow(bytes_to_long(sign),self.e,self.n))==message

p=getPrime(512)
q=getPrime(512)
e=65537
rsa=RSA(p,q,e)

with open("sign.txt","w") as f1:
    with open("corrupted_sign.txt","w") as f2:
        for _ in range(6):
            message=os.urandom(64)
            sign=rsa.sign(message)
            corrupted_sign=rsa.corrupt_sign(message)
            assert rsa.verify(message,sign)
            f1.write(str(sign)+'\n')
            f2.write(str(corrupted_sign)+'\n')

enc=pow(bytes_to_long(flag),rsa.e,rsa.n)
print(f"n = {rsa.n}")
print(f"N = {rsa.N}")
print(f"e = {rsa.e}")
print(f"enc = {enc}")
'''
n = 99670316685463632788041383175090257045961799409733877510733415402955763322569510896091638507050126669571444467488936880059210773298729542608112756526719533574432327269721804307073353651955251188547245641771980139488000798458617636759823027148955008149512692983471670488580994385743789385091027299901520585729
N = 81332992898551792936282861980393365170738006789835182134055801566584228471896473385776004610279937176800796971820133195300006470892468060034368863410462219133248069442508287516929262751427926825122839525496671527936622212986733708071962237633082743396115729744192159064241674410003857168101669882043743570731
e = 65537
enc = 2476965183785968993595493003363618829317072815989584886372189393899395623714779397354978469504773556228655475355703015337932838278988328384587983506790841663233499939173166353582189202860394411808445422387063648198432242875738065748287034529713834303346017134249834382745931627301273142828893469374138264396
'''
```

出题论文：<https://eprint.iacr.org/2011/388.pdf>
这题一开始是搜到了论文，瞟了两眼，以为不是，就没看下去了。。。
后来学长发给我这篇，我焯了两个钟复现出来了，说不定真有机会现场解出，唉还是太菜。
照着论文的 Attack Summary 敲就行了，一开始没理解到 $z$ 向量的意思，直接从格子拿，跑不出来，学长问我 $a$ 和 $b$ 的选取是不是有问题，我才知道要枚举出所有 $x$ 和 $y$ 。然后 $a$ 和 $b$ 在 0 到 10 间选取也不行，改成了 -10 到 10 。
exp 如下：

```python
from tqdm import tqdm
from itertools import combinations
from sage.all import *
from Crypto.Util.number import *
co_sig = [b"\x17\x8bb3\x11\x1b\xb9\xb9\xc6M\xb0\xaa\x07-\x1ar\xff\xfb\xb4&H7!\xb8\xa1\xce\x07\x8b\x84M\x0bw=m\x193Oc\x97w\x8f\xffy4\xa1\x99\xfcW\xf9|\xeb\xa4\x00\x1eD*\xe8-'\xa9\xef\x9d\x13*\xf4\xbe\x9d\x9b&w\xcb\xfd\xb3\xb6\xa3n\xb8\xb4\x97vT\xec@\x86\xd1R\xb0\n\xe1uC\xbc\x14\xeb\xceSu&'{\xb9\x12\x90\x82\xc7,\xdbr\xebP\xe1j\x11E\xd5\x17\xe1\xd0D\xe7z\x94vt\xbf\x1a\xc4+",
          b'\x1dJ\xc5\xb2\xbe\x05\xe6\xc8T\n\xbe"\xbeU\xed\xba\xec\x85\x05\x8b\x8ayE\xa3}0\x1dk\xa7\x10\xe2E\x19\xfe\x10\x90\xef\r\xdbV\x8b\x87|(\xd1\xb5\xfd\xb9\x14\x84\x05\x03\x81\xc8\xf6\xe5\x8a\x92\xa0\x01I\x8aG:\xc19\x9e\xf0\x8eZ\\Yx\x80|\xb7\x80\x0e\xcd\xa3\xba6\xf8\x98\xb1pB\x05\x8aT#\xbf\x1e\x1b~\xcb\xf5\t\xa2H9\xc9n\x81e\xa2\x15\x97\x11\xe4\x93\xf2\xe6\x80\x97\x99G\xb5\xfe\x07/\xd2\xbd\xad\xcf\x04\x9e\xd0',
          b'Gs\xda\xb8\x8a\x85\xccK\xf7\xa8y\x16\xa5\xf0\x06\xbe\xeb\x83&}a\x85q\x8d:\x1fSb\xb8\xc5\x84\xba*[\xe7\xbb{\x86\xd3\xb3r\xb6\xaaCN\x93\x1d<(\xe2\x1c;\x8crU\x8fD=W\xa7\x0b\xc7\xeag\x96\x06\xd6\xbb\xe4\x04b\xd8\x02\x12\xd6\xfa2\x1e#\xf0\xde\x8b\x88M\xd2\xf47\\\x98\xe0\x04Fu\x1bsy\xf2\xc4\xad\xd6Y\x81u~B:\xd2\x1f\xb3\xab\x01:\xfa\xdf\x19J8\xd0\x18RN\xfe,CA\x15\xb3\xe0',
          b"0I\xda5\x9f\x05v\x17\xdc\xd4q\xd6\x83,\x9d\r\xccc\x8a\xa1\xd4U\xd3\x18\xc9\xc6g\xcd\nX\x99Ah\xed}\xf3\xb1(\xd5I\xc6\x0f@yw9\x9d\xfdv\x15x\xeaRA\xd6\xb0\x1e\xb5B\xe5\x05cc\x06m\xf4NN'\x02q\x1a\x11\xe4\x87P:\xc8\x11a\x9f\xbd\x9c\x98x\xda\xea\xc4\xa8f\x89s\xcaJ\x7f\xeb\xd8\xc1G#\xf4\xdc\xe2\x01\xf2\xa5\x95\x19`)2!\xf5\xb9\xf0\xf2\xbb\xf8\x0bF&&`\xfd*\xe1\xf2\x9c",
          b':\x99/Hxt\xd1\xd4\xaaB\xd6H\x16\xe1\xc9\xe2\xb3\xc3\xa9b\xd3\x96\x9c\x05x6\xf1\xc3d\xa2\xd1U+.\x1b\xac^\xf6Mh7\xb7\x03\x8e\xdc\xca\x0bn\xac\xed\x92\xb8x\x04)\x0f|\x11\xcc\xfa\xf2\\\xba\xee\xc4X\xa8(\x05\xf2\xb5\x8f&\xf3\xff\x1eB\xe7\x94\xf4\xa6\x00!\xe5v\xd9x\xf0s\x94\xf4D(\xa9g\x118\xa7z\x83\xad\xdb\xe6\xe3\xe7\xf8\xf2\xef\xe5@\xe9\x13\x00OB\xcc\x05\xd1,_=\xd2/Og\x81\xa6+',
          b'\x1c|\xb6\xcc\xdfj\xc5\xa0s\xac w\xa6\xf2\x87D\xe3\xf9Y\xf5=\xf0\x0b\xd9\xea\x89,+e\x1e\xb7m#\x99\xd1\x87\x17Z\xed\x1d\xc8\x97;\xa0K\x05.\xaa<\xc6s\xcf\xa2\xa2\\PO\x12&\xb4\x11\xec\xad\x10\xf8\xf7\xd1\xd3_\x80\x17\xe0\x1eP\x93\xe3\xc2\x1e\x03\xea]^\xc6a\x9c\xcb\x90\xbb\x9f\x8by\xa5dhM\xce\xc7\xbc\xf7\xafe\xcf\xc1\xf1\x18@\x1e\xe2\xdb\xfb\xe4^\xc8\xe7\x19\xccnY\xc6o\x7fL\x9fV\xd4\xc4\x15\xe8',
          ]
sig = [b'\t\x8b\xde\x98\x84\x1d\x9e\xd4\xa0\xb7f\xe0\x05\xb1\xbd8\xb9G\xe3\x0c\x83\x8a\xe5\xf0G7\x12\x1eT\x85o-B\xe4_\xd2\x04\xd9:\xab\xdf\xa1 \x8f\xedt+\x0f\xce\xb5\x90\xaaK\xf0U~v=\x84\xe7$G\xf5\xfb\xd3ok~V\x1a\xec&\x15\x18Y\x0c\x80u\xafF\xf1\x10\x9f\xf2\xe6\xa6\x9a\xbb\xbd+\xa4l\xa9\x11\xd5\t\x13\x16\xa3\xde\xe1\xdfZ\xa9$r\xb5`\xc9"\x11\xab\xc5\x87\xc4\x1d@\x9e\xa4t\xdb#\xbdj\xcb\x95\xefK',
       b'z/\xd6\xfb\xd8\xfa\xc4\xed\xbd\x99\xd0\xa0\x90\xcb\xca\x83\xd8B\xa7\xf4\xbd\xe0\xc2&\x1aQl(\xd6p\x8f\x89=tT\xf1(\xeb\xab\x84[oR\x1fl=\xda\xf5\x18q\x8f\xa7k\x00\x1b\x1a\x0ei\x1fa.ho\x15\x04\x12\xe4\xc2\xd7\x19\x92\xc3\x9b\xfe\xd5\xb6R\xf8\x95\x9fr\x93\xddD\x1c[\x873\xd5\x06\x1b\xa5\x82/6\x9a\x13\xcf\xa4\xcd\x0e]\t\xad?\xd6\x84\r\x90\xef\x86\xf15)\xe34\xf7\xb77\xef\x0c&\xdb8\xa6\xe0\xa5a',
       b'U\x0b\xf6\x9cm])1\xe2\xad\xf9G\x8f\xa2\xbc}\xd7\x18\x89\xa4\xfdFQ\x80m"\xf9\to^\xd9A\x98\xd2\xca\x1e(b\xa8\xbe\xc2m\xf7\n[O\x00\xbc\x87\x17\xed\x0cG\xf2=H\x0e\xc0\x14+\xcb\xd0\x1feT2\xf2Th\xec\xc2\xcf>6,<\x88X\x8f\xe9g\xa8\x00\xafr\x05\x95\rj\x9c\xc6\n\xbb\x8a\x019\xc1\x1ef#\x02[Rh\xd8\xdc|{6\xeb\xe8U\x91\xa4\xeb}\xf4s;E\xe72$i\xdft\xff\'',
       b'[\x94\x95T\xf4\xc4\xca\x8drO\x80\x14\xc9<H\xa2a\xdc\xf4`\xac>\xab\x03\xfa\x80Sx\x99\x14\x83$U\x0b\xfa\x8fv\xfd\xda\x1a\xa0\xebY\xaa\x01\xe2XsG\t\xcf\xae\xa0\xbf\x82iG\tQ \xb1\xfe\xa5k\x12\xd9\x12\xf7\x95\xa3\xa5\x8d`z\x19\x1a\x90-\x9aj\x15\xf6f>\x18\x08\xb8\x1f\x88\x1a\x80Th\xd0\x15\x9bw#\'`K\xa5\xf1\xbf"\xe79\xaf\xc7z%p\xa5\x9f\x14\xef\'1\x11\x05Gg\xe9\xda\xc9\x18~[',
       b':\xefRE\xd7\xa1?\xf3\xb5\xf7\xdd\xe2\xb6~\x85014\xc0\x8a\x80\xe1\xb5#\x94\x10\xb2\xa0\xfe\x87\xd1t\xc3$&\xde8\x195\xcd\xf4@3\x15\xcaK\xcc\xcd\r:\x83*\xd7l\xb6\xf2} \tJ\xb5xKfjh.\xfb\xb5\x91\xc6\xf2x\x8e\x83\xdc\xc3\xef\x8b\x8dW\xa6\xa6\xb0w\xd8\xf2G\xa5-\xc3\x87\x17;\xedH`:\xcd\x08ts\x9eqPE\xd7\xfc\xc4\x98\xb5\xe0\xad\xb7A\x7f\xcb\x01\xbd\x98\xd3Ea\xb9\x07\x80\xf8\x19',
       b"8\xca\x7f!;\\\xde\x1b\x80i\x9b!\x1c??u\x13\x955\xd0xG\xff\xd7\xba\xfe+\x95\x0eu^\x15\x1a\x0e*\xfe\x8a\xafM\xc0\xd1Ty\xd7\xf1\xa7@\xd6\xa6\xee\x0c:It\x1a\xeag\xfc\x0c\xaf\x02<\x03T)\xeb\xb0\x15\x1cz\x85\x992\xa9\xbe\x9bm\xc4D\x83\xf7\xb5T\xdd9?\x94\xd4\x13\xb4\xb3\x8d\xa9\x92\x9dt\x86\xdb\x0b$\x19l\xb1\xb9\x05'o\xf3!\t\x01\x93'z\x15P\x88\xd7iN\n\x8bA\xb5\xd2}\xe8\x10"
       ]
n = 99670316685463632788041383175090257045961799409733877510733415402955763322569510896091638507050126669571444467488936880059210773298729542608112756526719533574432327269721804307073353651955251188547245641771980139488000798458617636759823027148955008149512692983471670488580994385743789385091027299901520585729
N = 81332992898551792936282861980393365170738006789835182134055801566584228471896473385776004610279937176800796971820133195300006470892468060034368863410462219133248069442508287516929262751427926825122839525496671527936622212986733708071962237633082743396115729744192159064241674410003857168101669882043743570731
e = 65537
enc = 2476965183785968993595493003363618829317072815989584886372189393899395623714779397354978469504773556228655475355703015337932838278988328384587983506790841663233499939173166353582189202860394411808445422387063648198432242875738065748287034529713834303346017134249834382745931627301273142828893469374138264396


def orthogonal_lattice(B):
    _d, _n = B.nrows(), B.ncols()
    _c = 2 ** min(((_n-1)/2+(_n-_d)*(_n-_d-1)/4), 20)
    for b in B:
        _c *= b.norm()
    B_bot = (ceil(_c)*B).stack(identity_matrix(ZZ, _n))
    B_r = B_bot.transpose().LLL()
    LB = B_r.matrix_from_rows_and_columns(range(_n-_d), range(_d, _n+_d))
    assert (B*LB.transpose()).is_zero()
    return LB


v = [crt([bytes_to_long(co_sig[i]), bytes_to_long(sig[i])], [N, n])
     for i in range(6)]

Lv = orthogonal_lattice(matrix(ZZ, v))

result = orthogonal_lattice(Lv.matrix_from_rows(range(0, 6-2)))

for x, y in combinations(result, 2):
    for a in tqdm(range(-10, 10)):
        for b in range(-10, 10):
            z = a*x+b*y
            if z.norm() > sqrt(6*n):
                continue
            else:
                vv = vector(v)-z
                for i in vv:
                    if gcd(i, n) != 1:
                        p = gcd(i, n)
                        assert n % gcd(i, n) == 0
                        q = n//p
                        phi = (p-1)*(q-1)
                        d = inverse_mod(e, phi)
                        m = long_to_bytes(int(pow(enc, d, n)))
                        print(m)
                        exit()
```

### 原理

RSA-CRT签名中计算了：
$$
\sigma_p=\mu(m)^d\mod \ p \\\\  \sigma_q=\mu(m)^d\mod \ q
$$
然后签名 $\sigma=\sigma_p\cdot\alpha+\sigma_q\cdot\beta$ ，其中 $\alpha=q\cdot(q^{-1}\mod\ p)$ ， $\beta=p\cdot(p^{-1}\mod\ q)$ 。
题目中给出 6 对签名，每对签名用 CRT 不难算出
$$
v=\sigma_p\cdot\alpha+\sigma_q\cdot\beta \mod N\cdot N'
$$
其中 $\sigma_p$ 和 $\sigma_q$ 和 $N/2$ 一个数量级， $\alpha$ 和 $\beta$ 又和 $N$ 一个数量级，故右式远小于 $N\cdot N'$ ，那么**上式在整数域上是成立的**。
一对算不出，但是多对可以，组成向量，有：
$$
\boldsymbol{v}=\alpha\boldsymbol{x}+\beta\boldsymbol{y}
$$
其中 $\boldsymbol{x}$ 和 $\boldsymbol{y}$ 是分量 $n/2$ 位的未知向量， $\alpha$ 和 $\beta$ 是有关 $p$ 和 $q$ 的 CRT 系数。
不难计算出一组与 $\mathbb{Z}^\ell$ 中正交于 $\boldsymbol{v}$ 的向量的格 $\boldsymbol{v}^\bot \in \mathbb{Z}^\ell$ 的约化基 $\{\boldsymbol{b}_1,...,\boldsymbol{b}\_{\ell-1}\}$ 。（可能此时你会疑惑为什么是 ${\ell-1}$ 个向量，下面的拓展里有解释）
特别地，我们有：
$$
\alpha \langle \boldsymbol{b}_j,\boldsymbol{x} \rangle + \beta \langle \boldsymbol{b}_j,\boldsymbol{y} \rangle = 0 \quad \mathrm{for} \ j=1,2,\ldots,\ell-1
$$
~~（也不是很特别的感觉）~~
现在观察方程 $\alpha\cdot u+\beta\cdot v=0$ ，最小的非零解 $(u,v)\in \mathbb{Z}^2$ 是 $\pm(\beta,-\alpha)/g$ ，其中 $g=\gcd(\alpha,\beta)$ 盲猜是非常小的（经测试基本在10以内），意味着 $|u|,|v|\geq\mathit{\Omega}(N)$ 中 $\mathit{\Omega}$ 常量是非常小的。（啥玩意？）对 $j=1,2,\ldots,\ell-1$ ，有以下两种可能：

**情形1**：$\langle \boldsymbol{b}_j,\boldsymbol{x} \rangle = \langle \boldsymbol{b}_j,\boldsymbol{y} \rangle = 0$ 。此时 $\boldsymbol{b}_j$ 属于 $\mathbb{Z}^\ell$ 中与 $\boldsymbol{x}$ 和 $\boldsymbol{y}$ 正交的向量的格 $L=\{\boldsymbol{x},\boldsymbol{y}\}^\bot$

**情形2**：$\langle \boldsymbol{b}_j,\boldsymbol{x} \rangle$ 和 $\langle \boldsymbol{b}_j,\boldsymbol{y} \rangle$ 有绝对值 $\geq \mathit{\Omega}(N)$ ，其中 $\mathit{\Omega}(N)$ 是一个小常数。因为 $\boldsymbol{x}$ 和 $\boldsymbol{y}$ 的范数都不超过 $\sqrt{\ell N}$ ，由柯西-施瓦茨不等式，这意味着 $||\boldsymbol{b}_j||\geq \mathit{\Omega}(\sqrt{\ell N})$

因为格 $L=\{\boldsymbol{x},\boldsymbol{y}\}^\bot$ 的秩是 $\ell-2$ ，当全部 $\ell-1$ 个向量 $\boldsymbol{b}\_j$ 线性无关时情形1不成立，所以最长的 $\boldsymbol{b}\_{\ell-1}$ 应该在情形2中，因此 $||\boldsymbol{b}\_{\ell-1}||\geq \mathit{\Omega}(\sqrt{\ell N})$ 。另一方面，其他向量形成一个秩为 $\ell-2$ 的格，且体积
$$
V=\mathrm{vol}(\mathbb{Z}\boldsymbol{b}\_1\oplus\cdots\oplus\mathbb{Z}\boldsymbol{b}\_{\ell-2})\approx\frac{\mathrm{vol}(\boldsymbol{v}^\bot)}{||\boldsymbol{b}\_{\ell-1}||}=\frac{||\boldsymbol{v}||}{||\boldsymbol{b}\_{\ell-1}||}\leq \frac{\sqrt{\ell}\cdot N^{3/2}}{\mathit{\Omega}(\sqrt{N/\ell})}=O(\ell N)
$$
盲猜是一个随机的格。特别地，我们有：
$$
||\boldsymbol{b}\_j||=O(\sqrt{\ell-2}\cdot V^{1/(\ell-2)})=O(\ell^{1/2+1/(\ell-2)}\cdot N^{1/(\ell-2)})\quad\mathrm{for} \ j=1,2,\ldots,\ell-2
$$

一旦 $\ell \geq 5$ ，这个长度就远小于 $\sqrt{N/\ell}$ 。假设是这种情况，那么对于 $j=1,2,...,\ell-2$ ， $\boldsymbol{b}\_j$ 应该是情形1中。这意味着这些向量生成 $L=\{\boldsymbol{x},\boldsymbol{y}\}^\bot$ 中一个满秩的子格 $L'=\mathbb{Z}\boldsymbol{b}\_1\oplus\cdots\oplus\mathbb{Z}\boldsymbol{b}_{\ell-2}$ 。
取正交格，我们得到 $(L')^\bot \supset L^\bot=\mathbb{Z}\boldsymbol{x}\oplus\mathbb{Z}\boldsymbol{y} $。因此， $\boldsymbol{x}$ 和 $\boldsymbol{y}$ 属于 $L'$ 的正交格 $(L')^\bot$ 。令 $\{\boldsymbol{x'},\boldsymbol{y'}\}$ 为一组该格的约化基，我们可以枚举 $(L')^\bot$ 中的长度不超过 $\sqrt{\ell N}$ 且为 $\boldsymbol{x'}$ 和 $\boldsymbol{y'}$ 线性组合的所有格向量。高斯启发式表明这大约为：
$$
\frac{\pi(\sqrt{\ell N})^2}{\mathrm{vol}((L')^\bot)}=\frac{\pi\ell N}{V}=O(1)
$$
这样的向量，所以这肯定是可行的。对这些向量 $\boldsymbol{z}$ ，我们计算 $\gcd(\boldsymbol{v}-\boldsymbol{z},N)$ 。我们将因此很快在其中找到 $\gcd(\boldsymbol{v}-\boldsymbol{x},N)$ ，因为 $\boldsymbol{x}$ 是一个 $(L')^\bot$ 中长度 $\leq\sqrt{\ell N}$ 的向量。但根据 $\boldsymbol{v}$ 的定义，我们有：
$$
\boldsymbol{v}=\boldsymbol{x}\mod p\\\\
\boldsymbol{v}=\boldsymbol{y}\mod q
$$
故 $\gcd(\boldsymbol{v}-\boldsymbol{x},N)=p$ ，从而分解 $N$ 。

### 拓展阅读-正交格

令 $\mathbf{b}_1,...,\mathbf{b}_d$ 为 $\mathit{\Lambda}$ （这玩意念Lambda）中的向量。如果这 $d$ 个向量在 $\mathbf{Z}$ 上线性无关且 $\mathit{\Lambda}$ 中的任意元素可以由 $\mathbf{b}_i$ 整系数线性表出，则这 $d$ 个向量形成 $\mathit{\Lambda}$ 中的一组基。 $\mathit{\Lambda}$ 中至少存在一组基。 $\mathit{\Lambda}$ 的基都有相同的基数，称为 $\mathit{\Lambda}$ 的维度。

如果 $\mathit{\Omega}$ 包含 $\mathit{\Lambda}$ ，且两者有相同的维度，则称 $\mathit{\Lambda}$ 为 $\mathit{\Omega}$ 在 $\mathbf{Z}^n$ 上的一个子格。（子格的定义？） $\mathit{\Lambda}$ 的所有基张成相同的 $\mathbf{Q}^n$ 的 $Q$ 向量子空间（啥玩意？），记为 $E_{\mathit{\Lambda}}$ 。 $\mathbf{Q}^n$ 上 $E_{\mathit{\Lambda}}$ 的维度与 $\mathit{\Lambda}$ 的维度相同。令格 $\overline{\mathit{\Lambda}}=E_{\mathit{\Lambda}}\cap\mathbf{Z}^n$ 。 $\mathit{\Lambda}$ 是 $\overline{\mathit{\Lambda}}$ 的一个子格。如果 $\mathit{\Lambda}=\overline{\mathit{\Lambda}}$ ，那么我们称 $\mathit{\Lambda}$ 是一个完备格，特别的， $\overline{\mathit{\Lambda}}$ 是一个完备格。

> 笔者注记：
这里首先将 $\mathit{\Lambda}$ 张成一个**有理数空间**，不局限于**整系数**向量组合了，记为 $E_{\mathit{\Lambda}}$ 的E我猜是**欧几里得**的意思？然后与 $\mathbf{Z}^n$ 相交得到的是整数点集合 $\overline{\mathit{\Lambda}}$ ，如此 $\mathit{\Lambda}$ 是 $\overline{\mathit{\Lambda}}$ 子格的事应该挺自然的。然后如果两者相等，想象一下，都那样张成了都找不到新的点，那这个格确实也挺完备。
PS:发现自己念了十年的欧几里得，难怪输入法打不出来（）

令 $(\mathbf{x},\mathbf{y})\rightarrow\mathbf{x}.\mathbf{y}$ 为一般意义上的欧里几德内积， $||.||$ 是它对应的范数 ~~（奇怪的表示方法）~~。令 $F=(E_{\mathit{\Lambda}})^-$ 是关于该内积的正交向量子空间。我们定义正交格 $\mathit{\Lambda}^-=F\cap\mathbf{Z}^n$ 。因此， $\mathit{\Lambda}^-$ 是一个 $\mathbf{Z}^n$ 上的完备格，其维度为 $n-d$ 。这意味着 $(\mathit{\Lambda}^-)^-$ 等于 $\overline{\mathit{\Lambda}}$ 。令 $\mathcal{B}=(\mathbf{b}_1,...,\mathbf{b}_d)$ 为 $\mathit{\Lambda}$ 的一组基。

> 笔者注记：
看到这就有点迷糊了，捋一捋： $E_{\mathit{\Lambda}}$ 是 $\mathit{\Lambda}$ 张成出的有理空间，然后 $F$ 是其正交向量子空间，即**任意从 $\mathit{\Lambda}$ 和 $F$ 分别抓两个向量出来，其内积都为 $0$** 。
再然后 $\mathit{\Lambda}^-$ 是 $F$ 的一个子格，**注意到 $\mathit{\Lambda}^-$ 把 $F$ 所有整数点都框进去了**，这就很有意思了，由上面的定义就不难得出正交格 $\mathit{\Lambda}^-$ 是一个 $\mathbf{Z}^n$ 上的完备格。
至于其维度为何是 $n-d$ ，有个概念叫**正交补**，就是正交空间的维数是刚刚好的，对于列空间维数为 $r$ 的矩阵 $A_{r\times m}$ ，其左零空间的维数是 $m-r$ ，相加恰好为 $m$ 。举例来说，三维中与线正交的是二维空间，与面正交的是一维空间。
这篇 paper 习惯用 $E^-$ 表示正交向量子空间，但似乎 $E^\bot$ 的写法较为广泛。

在 $\mathbf{Z}^n$ 的正则基上解析每个 $\mathbf{b}_j$ 如下：

$$
\mathbf{b}\_j =
\begin{pmatrix}
b_{1,j} \\\\
b_{2,j} \\\\
\vdots \\\\
b_{n,j}
\end{pmatrix}
$$
（这里吐槽一下，由于下划线和 Markdown 语法有冲突，如果不加反斜杠， $b_j$ 写成 $\mathbf{b}_j$ Latex 就会炸，下文一开始也炸了几回，弄了几次才发现是这问题）

定义整数 $n\times d$ 的整数矩阵 $B=(b_{i,j})_{1\leq i\leq n,1\leq j\leq d}$ ，格 $\mathit{\Lambda}$ 由 $B$ 的列向量张成，我们称 $\mathit{\Lambda}$ 由 $B$ 张成。令 $Q={^tB}B$ 为 $d\times d$ 的对称 Gram 矩阵。 $Q$ 的行列式是与 $\mathcal{B}$ 无关的正整数。 $\mathit{\Lambda}$ 的行列式被定义为 $\det(\mathit{\Lambda})=\sqrt{\det(B)}$ 。

> 笔者注记：
这是的 ${^tB}$ 应该是 $B^T$ 的意思，又是奇怪的写法（）
至于 Gram 矩阵，中文音译为格拉姆矩阵，对 $n$ 维欧氏空间上的 $k$ 个向量，其 Gram 矩阵为
$$
\triangle(\mathbf{v}_1,\dots,\mathbf{v}_k) =
\begin{pmatrix}
\langle\mathbf{v}_1,\mathbf{v}_1\rangle & \cdots & \langle\mathbf{v}_1,\mathbf{v}_k\rangle \\\\
\vdots & \ddots & \vdots \\\\
\langle\mathbf{v}_k,\mathbf{v}_1\rangle & \cdots & \langle\mathbf{v}_k,\mathbf{v}_k\rangle
\end{pmatrix}
$$
不难看出这个可以等价表示为 $V^T\times V$ ，得出的矩阵也显然是对称的。
这里 $\mathit{\Lambda}$ 不是一个方阵，故不能直接求出其行列式，那么就应该通过其 Gram 矩阵来求行列式，这里我觉得应该是 $\det(\mathit{\Lambda})=\sqrt{\det(Q)}$ ，但我不确定。

**定理1** 令 $\mathit{\Lambda}$ 为 $\mathbf{Z}^n$ 上的完备格，那么 $\det(\mathit{\Lambda}^-)=\det(\mathit{\Lambda})$ 。
证明：我们有 $\mathit{\Lambda}=E_{\mathit{\Lambda}}\cap\mathbf{Z}^n$ 和 $\mathit{\Lambda}^-=E_{\mathit{\Lambda}}^-\cap\mathbf{Z}^n$ 。从另一篇论文（我也没读过）我们知道：
$$
\det(\mathbf{Z}^n)=\frac{\det(E_{\mathit{\Lambda}}\cap\mathbf{Z}^n)}{\det((E_{\mathit{\Lambda}}^-)\cap(\mathbf{Z}^n)^*)}
$$
其中 $(\mathbf{Z}^n)^*$ 表示 $\mathbf{Z}^n$ 上的极格。但 $\det(\mathbf{Z}^n)=1$ （？为什么要说但呢？）且 $(\mathbf{Z}^n)^*=\mathbf{Z}^n$ ，故 $\det(\mathit{\Lambda}^-)=\det(\mathit{\Lambda})$ 。

**推论2** 令 $\mathit{\Lambda}$ 为 $\mathbf{Z}^n$ 上的格，那么 $\det((\mathit{\Lambda}^-)^-)=\det(\mathit{\Lambda}^-)=\det(\overline{\mathit{\Lambda}})$ 。

**定理3** 令 $(\mathbf{b}_1,...,\mathbf{b}_d)$为格$\mathit{\Lambda}$ 在 $\mathbf{Z}^n$ 上的一组 LLL 约化基，那么：

1. $\det(\mathit{\Lambda})\leq \prod^d_{i=1}||\mathbf{b}_i||\leq 2^{d(d-1)/4}\det(\mathit{\Lambda})$
2. 对任意线性无关的向量 $\mathbf{x}_1,...,\mathbf{x}_t\in\mathit{\Lambda}$ ，当 $1\leq j \leq t$ 时，有：
$$
||\mathbf{b}_j||\leq 2^{(d-1)/2}\max(||\mathbf{x}_1||,...,||\mathbf{x}_t||)
$$

我们现在描述计算正交格的一组 LLL 约化基的基本方法。令 $\mathcal{B}=(\mathbf{b}_1,...,\mathbf{b}\_d)$ 为 $\mathit{\Lambda}$ 的一组基， $B=(b\_{i,j})$ 为其对应的 $n\times d$ 的矩阵。令 $c$ 为一个正整数常量。定义 $\mathit{\Omega}$为$\mathbf{Z}^{n+d}$ 上由以下 $(n+d)\times n$ 矩阵张成的格。

$$
B^-=
\begin{pmatrix}
c\times b_{1,1} & c\times b_{2,1} & \cdots & c\times b_{n,1} \\\\
c\times b_{1,2} & c\times b_{2,2} & \cdots & c\times b_{n,2} \\\\
\vdots & \vdots & \ddots & \vdots \\\\
c\times b_{1,d} & c\times b_{2,d} & \cdots & c\times b_{n,d} \\\\
1 & 0 & \cdots & 0 \\\\
0 & 1 & \cdots & 0 \\\\
\vdots & \vdots & \ddots & \vdots \\\\
0 & 0 & \cdots & 1
\end{pmatrix}
$$
矩阵 $B^-$ 被分成两块：上面 $d\times n$ 部分是 $c\ {^tB}$ ，下面 $n\times n$ 部分是单位阵。
设 $p_{\uparrow}$ 和 $p_{\downarrow}$ 是两个投影，将 $\mathbf{Z}^{n+d}$ 的任何向量分别映射到由其前 $d$ 个坐标构成的 $\mathbf{Z}^d$ 向量和由其最后 $n$ 个坐标构成的 $\mathbf{Z}^n$ 向量，所有投影都与正则基有关。~~（这段翻译累死我了）~~
令 $\mathbf{x}$ 为 $\mathit{\Omega}$ 的一个向量并记 $\mathbf{y}=p_{\downarrow}(\mathbf{x})$ ，那么

$$
p_{\uparrow}(\mathbf{y})=
\begin{pmatrix}
\mathbf{y}.\mathbf{b}\_1 \\\\
\vdots \\\\
\mathbf{y}.\mathbf{b}\_d
\end{pmatrix}
$$
因此，当且仅当 $p\_{\uparrow}(\mathbf{x})=0$ 时有 $\mathbf{y}\in \mathit{\Lambda}^-$ 。此外，如果 $||\mathbf{x}||\leq c$ ，那么 $p_{\uparrow}(\mathbf{x})=0$ 。

**定理4** 令 $(\mathbf{x}_1,\mathbf{x}_2,...,\mathbf{x}_n)$ 为格 $\mathit{\Omega}$ 的一组 LLL 约化基。若

$$
c>2^{(n-1)/2+(n-d)(n-d-1)/4}\det(\overline{\mathit{\Lambda}})
$$
则 $(p_{\downarrow}(\mathbf{x}\_1),p_{\downarrow}(\mathbf{x}\_2),...,p_{\downarrow}(\mathbf{x}_{n-d}))$ 为 $\overline{\mathit{\Lambda}}$ 的一组 LLL 约化基。

使用阿达马不等式，我们得到以下算法：

**算法5** 给定一组 $\mathbf{Z}^n$ 上格 $\mathit{\Lambda}$ 的基 $(\mathbf{b}_1,\mathbf{b}_2,...,\mathbf{b}_d)$ ，该算法计算一组 $\overline{\mathit{\Lambda}}$ 的LLL约化基。

1. 选取 $c=\lceil2^{(n-1)/2+(n-d)(n-d-1)/4}\prod^d_{j=1}||\mathbf{b}_j||\rceil$

2. 计算 $(n+d)\times n$ 的整数矩阵 $B^-$ 和 $\mathbf{b}_1,...,\mathbf{b}\_d$ 对应的 $n\times d$ 矩阵 $B=(b\_{i,j})$

3. 计算由 $B^-$ 张成的格的一组 LLL 约化基 $(\mathbf{x}_1,\mathbf{x}_2,...,\mathbf{x}_n)$

4. 输出 $(p_{\downarrow}(\mathbf{x}\_1),p_{\downarrow}(\mathbf{x}\_2),...,p_{\downarrow}(\mathbf{x}_{n-d}))$

可以证明，这是一个关于空间维数 $n$ 、格维数 $d$ 和 $||\mathbf{b}_j||$ 比特长度的任何上界的确定性多项式时间算法。在实践中，不需要选择这样大的常数 $c$ ，因为 LLL 算法的理论界非常悲观。（翻译了这么久都看不懂，我也很悲观.jpg）

> 笔者注记：
$\lceil$和$\rceil$表示向上取整，例如$\lceil 1.2 \rceil = 2$。

#### 实现

之前看过 Herry 师傅从 dbt 那抄的一个求法是用左零空间求解，代码如下

```python
def orthogonal_lattice(B):
    LB = B.transpose().left_kernel(basis="LLL").basis_matrix()
    return LB
```

但笔者发现这样似乎只能在低维下求解，高维情况下时间会爆炸（至少试过一夜都没跑出来）
于是照着 paper 搓了一个 implemention ，快了很多，三分钟左右就能求解 $255\times512$ 矩阵的正交格，代码如下

```python
def orthogonal_lattice(B):
    _d, _n = B.nrows(), B.ncols()
    _c = 2 ** min(((_n-1)/2+(_n-_d)*(_n-_d-1)/4),20)    # this bound can be adjusted as needed
    for b in B:
        _c *= b.norm()
    B_bot = (ceil(_c)*B).stack(identity_matrix(ZZ, _n))
    B_r = B_bot.transpose().LLL()
    LB = B_r.matrix_from_rows_and_columns(range(_n-_d), range(_d,_n+_d))
    assert (B*LB.transpose()).is_zero()
    return LB
```

## 参考

* [P. Q. Nguyen and J. Stern. Merkle-Hellman revisited: A cryptoanalysis of the Qu-Vanstone cryptosystem based on group factorizations. In B. S. Kaliski Jr., editor, CRYPTO, volume 1294 of Lecture Notes in Computer Science, pages 198–212. Springer, 1997.](https://link.springer.com/chapter/10.1007/BFb0052236)

* [Modulus Fault Attacks Against RSA-CRT Signatures](https://link.springer.com/article/10.1007/s13389-011-0015-x)

* [知乎 线性代数之——正交向量与子空间](https://zhuanlan.zhihu.com/p/50483906)

* [知乎 格拉姆矩阵（Gram matrix）详细解读](https://zhuanlan.zhihu.com/p/187345192)
