#import "../../../config.typ": *

#show: template-post.with(
  title: "复变函数笔记",
  description: "高数写了笔记再考试效果挺好的 ~~（为什么挂科之前没这觉悟啊）~~，复变也记一下吧",
  tags: ("数学", "高数", "复变函数",),
  category: "Course",
  date: datetime(year: 2022, month: 10, day: 9)
)

== 复数与复变函数

=== 复数及其运算

通常记复数为 $z=x+"i"y$ ，其中实部与虚部记作
$ x="Re"(z),quad y="Im"(z) $
显然
$ "Re"(z)=fracz+overline(z)2,quad "Im"(z)=fracz-overline(z)2"i" $
以正实轴为始边，以 $z(z!= 0)$ 所对应的向量为终边的角称为复数 $z$ 的辐角，记作 $"Arg"\ z$ ，把在 $(-pi ,pi ]$ 之间的辐角称为 $z$ 的主辐角（或主值或者叫辐角主值），记作 $"arg"\ z$ 。
有个重要点就是辐角要*注意正负*。

以及大名鼎鼎的*欧拉公式*：$$e^{\mathrm{i}\theta}=\cos\theta+\mathrm{i}\sin\theta$$

一个没什么名但是*很有用*的公式——棣莫弗公式：$$z^n = \cos n\theta + \mathrm{i}\sin n\theta$$

*复数的开方*
复数开方时，开几次方就有几个结果。
求 $w=root(n, z)$ 时，令 $w=rho e^("i"phi.alt )$ ，从而 $rho ^n e^("i"nphi.alt ) = z = re^("i"theta )$ ，得到
$ rho ^n = r,quad nphi.alt = theta + 2kpi ,quad k=0,plus.minus 1,plus.minus 2,dots.c 
$$故 $
\rho = r^{1/n},\quad \varphi = \frac{\theta + 2k\pi}{n}
$$于是
$ w = root(n, r)e^("i"frac(theta + 2kpi , n)) $

=== 平面点集的一般概念

和高数类似，没啥好说的。

=== 复变函数

似乎也没啥重要的（）

== 解析函数

=== 解析函数的概念与柯西-黎曼方程

*奇点*：如果函数 $f(z)$ 在点 $z_0$ *不解析*，则称 $z_0$ 为 $f(z)$ 的奇点。
求*有理分式*的奇点时，直接取*分母零点*即可。

柯西-黎曼方程（C-R方程）：
$ frac(diff u, diff x) = frac(diff v, diff y),quad frac(diff u, diff y) = -frac(diff v, diff x) $

可导的充要条件： $u(x,y)$ 和 $v(x,y)$ 在点 $x,y$ 可微，且在该点满足C-R方程。

*例* 证明：柯西-黎曼方程的极坐标形式是
$ frac(diff u, diff r) = frac(1, r)frac(diff v, diff theta ),quad frac(diff v, diff r) = -frac(1, r)frac(diff r, diff theta ) $

=== 初等函数及其解析性

*指数函数* $z=x+"i"y$ 为任意复数，称 $w=e^z=e^x(cos y+"i"sin y)$ 为指数函数。

*对数函数* 满足方程 $e^w = z$ 的函数 $w="Ln" \ z$ 称为对数函数，且
$ "Ln"\ z = ln z + 2kpi "i" = ln |z| + "i""arg"\ z + 2kpi "i",quad k=0,plus.minus 1,plus.minus 2,dots.c $

*幂函数* $w=z^a=e^(a"Ln"\ z)$ 为幂函数。

*三角函数* 称 $sin z = frace^("i"z)-e^(-"i"z)2"i"$ 为正弦函数， $cos z = frace^("i"z)+e^(-"i"z)2$ 为余弦函数。

*双曲函数* 称 $sinh z = frace^z-e^(-z)2$ 为双曲正弦函数， $cosh z = frace^z+e^(-z)2$ 为双曲余弦函数。

=== 解析函数与调和函数的关系

若实二元函数 $phi.alt (x,y)$ 在区域 $D$ 内具有二阶连续偏导数，且满足 $"Laplace"$ 方程
$ frac(diff ^2phi.alt , diff x^2) + frac(diff ^2phi.alt , diff y^2) = 0 $
则称 $phi.alt (x,y)$ 为区域 $D$ 的调和函数。

*例* 验证 $u(x,y)=x^3-3xy^2$ 为调和函数，并求以 $u(x,y)$ 为实部的解析函数 $f(z)$ ，使得 $f("i") = -"i"$ 。

*解* $u_(xx)=6x$，$u_(yy)=-6y$，故 $u_(xx)+u_(yy)=0$， $u(x,y)$ 为调和函数。下面求虚部 $v(x,y)$ 。
*法一*：偏积分法
$ u_x = 3x^2-3y^2 = v_y => v = integral (3x^2-3y^2)"d"y = 3x^2y-y^3 + phi.alt (x) \\
v_x = 6xy+phi.alt '(x) = -u_y = 6xy => phi.alt (x) = C => v(x,y) = 3x^2y - y^3 + C $

*法二*：全微分法
$ v_y=u_x=3x^2-3y^2,v_x=-u_y=6xy\\
=> "d"v = v_x'"d"x +v_y'"d"y=6xy"d"x + (3x^2-3y^2)"d"y\\
=> v(x,y)=integral _((0,0))^((x,y))6xy"d"x+(3x^2-3y^2)"d"y + C \\
=integral _0^x"d"x+integral _0^y(3x^2-3y^2)"d"y + C = 3x^2y - y^3 + C $

最后代入 $f("i")=-"i"$ 有 $f(z)=(x^3-3xy^2)+"i"(3x^2y-y^3)=z^3$ 。

== 复变函数的积分

=== 复变函数积分的概念

*例* 计算 $I=integral.cont _(mathitGamma )frac(1, (z-z_0)^n)"d"z$ ，其中 $mathitGamma$ 为包含 $z_0$ 的一条闭曲线。
*解* 以 $z_0$ 为圆心 $r$ 为半径作圆，则函数 $f(z)=frac(1, (z-z_0)^n)$ 在 $overline(D)=D+mathitGamma +C^-$上解析，因此
$ I = integral.cont _Cfrac("d"z, (z-z_0)^n)"d"z
= begincases
2pi "i", & n = 0 \\
0, & n!= 0
endcases $

=== 柯西积分定理

设函数 $f(z)$ 在单连通域 $D$ 内解析， $mathitGamma$ 为 $D$ 内的任意一条简单闭曲线，则有$$\oint_{\mathit{\Gamma}}f(z)\mathrm{d}z=0$$
甚至也不用在$mathitGamma$ 上解析，在 $mathitGamma$ 上连续就成立。

=== 复合闭路定理

设多连域 $D$ 的边界为 $C=C_0 + C_1^- + C_2^- + dots.c + C_n^-$ ，函数 $f(z)$ 在 $D$ 内解析，在 $C$ 上连续，则
$ integral.cont _Cf(z)"d"z = 0 $
或
$ integral.cont _(C_0)f(z)"d"z = sum _(k=1)^nintegral.cont _(C_k)f(z)"d"z $

=== 柯西积分公式

*柯西积分公式* 若函数 $f(z)$ 在简单正向闭曲线 $C$ 所围成的区域 $D$ 内解析，在区域 $D$ 的边界 $C$ 上连续， $z_0$ 是区域 $D$ 内任意一点，则
$ f(z_0) = frac(1, 2pi "i")integral.cont _Cfrac(f(z), z-z_0)"d"z $

*高阶求导公式* 设 $f(z)$ 在 $D$ 内解析，在 $D$ 的边界 $C$ 上连续， $C$ 为正向简单闭曲线，则 $f^((n))(z)$ 在 $D$ 内解析，且有
$ f^((n))(z_0)=frac(n!, 2pi "i")integral.cont _Cfrac(f(z), (z-z_0)^(n+1))"d"z, quad forall z_0in D, n=0,1,2,dots.c $

== 解析函数的幂级数表示

=== 复级数的基本概念

复数列收敛和一般的数列收敛定义类似，其充要条件为
$ lim _(ntoinfinity )a_n=a,quad lim _(ntoinfinity )b_n=b $
所以判断级数收不收敛就*拆成实部和虚部*然后进行判断。

=== 幂级数

*收敛半径* 求法与高数类似，但多个根值法：
（1）（比值法） $lim limits_(ntoinfinity )|fraca_(n+1)a_n|=L$
（2）（根值法） $lim limits_(ntoinfinity )root(n, |a_n|)=L$
则收敛半径 $R=frac(1, L)$

幂级数性质与高数也类似，可以逐项求导和逐项求积。

=== 解析函数的泰勒展开

与高数类似，不再赘述。

*四个重要的已知展开*
$ frac(1, 1-z) = sum _(n=0)^infinity z^n = 1+z+frac(z^2, 2)+frac(z^3, 3!)+dots.c ,space |z| < 1 \\
e^z = sum _(n=0)^infinity frac(z^n, n!) = 1+z+frac(z^2, 2!)+frac(z^3, 3!)+dots.c ,space |z| < +infinity \\
sin z = sum _(n=0)^infinity frac(-1)^nz^(2n+1)(2n+1)! = z-frac(z^3, 3!)+frac(z^5, 5!)-frac(z^7, 7!)+dots.c ,space |z| < +infinity \\
cos z = sum _(n=0)^infinity frac(-1)^nz^(2n)(2n)! = 1-frac(z^2, 2!)+frac(z^4, 4!)-frac(z^6, 6!)+dots.c ,space |z| < +infinity $

*展开后注意标出收敛圆！*

=== 洛朗级数

泰勒展开有个缺陷，那就是只能展开到解析的地方，如果中间有个奇点卡住，那就不能再往外展开了。
这个时候就用到洛朗级数，可以在圆环域展开，弥补泰勒展开的不足。

== 留数及其应用

=== 孤立奇点

==== 零点的判断

首先很直白的， $f(z_0)=0$ ，那么 $z=z_0$ 就是 $f(z)$ 的零点。
若 $f(z)=(z-z_0)^mphi.alt (z)$ ， $phi.alt (z)$ 在 $z_0$ 处解析且 $phi.alt (z_0)!= 0$ ，则 $z=z_0$ 是 $f(z)$ 的 $m$ 阶零点。

==== 奇点类型的判断

从定义上判断的话就先展开成洛朗级数，即设 $z_0$ 为 $f(z)$ 的孤立奇点，将 $f(z)$ 在 $0 < |z-Z_0| < delta$ 内洛朗展开为 $f(z)=sum limits_(n=0)^(+infinity ) a_n(z-z_0)^n$ 。

+ 可去奇点：展开式中不含负幂次项，直观上看就是 $lim limits_(z-> z_0)f(z)=C$ 。
+ $N$ 阶极点：含有限多的负幂次项，且最高负幂次为 $N$ ，直观上看就是 $lim limits_(z-> z_0)f(z)=infinity$。
+ 本性奇点：含无穷多的负幂次项，直观上看就是 $lim limits_(z-> z_0)f(z)$ 不存在且不为 $infinity$ 。

=== 留数

==== 留数的定义

设 $z_0$ 为函数 $f(z)$ 的孤立奇点，将 $f(z)$ 在 $z_0$ 的去心邻域内展开成洛朗级数
$ f(z) = sum _(n=-infinity )^(+infinity )a_n(z-z_0)^n = dots.c + a_(-2)(z-z_0)^(-2) + a_(-1)(z-z_0)^(-1) + a_0 + a_1(z-z_0) + a_2(z-z_0)^2 + dots.c $
称 $a_(-1)$ 为 $f(z)$ 在 $z_0$ 处的留数，记作$$\mathrm{Res}[f(z),z_0]=a_{-1}=\frac{1}{2\pi i}\oint\limits_c f(z)\mathrm{d}z$$
其中 $C$ 是 $z_0$ 的去心邻域内绕 $z_0$ 的一条简单闭曲线。

==== 留数的求解

+ $z_0$ 为可去奇点： $"Res"[f(z),z_0]=0$ 。
+ $z_0$ 为本性奇点：需要将$f(z)$在$z_0$的去心邻域内展开成洛朗级数
+ $z_0$ 为 $m$ 阶极点：$$\mathrm{Res}[f(z),z_0]=\frac{1}{(m-1)!}\lim_{z\to z_0}\frac{d^{m-1}}{dz^{m-1}}[(z-z_0)^mf(z)]$$

==== 无穷远处的留数

若函数 $f(z)$ 在无穷远点 $infinity$ 的去心领域 $R<|f(z)|<+infinity$ 内解析，则称点 $infinity$ 为 $f(z)$ 的孤立奇点。

设函数 $f(z)$ 在圆环域 $R<|z|<+infinity$ 内解析，则 $f(z)$ 在 $infinity$ 处的留数为：
$ "Res"[f(z),infinity ]=frac(1, 2pi "i")integral.cont _(C^-)f(z)"d"z $
其中， $C$ 为 $|z|=rho > R$ 。

$ "Res"[f(z), infinity ] = -"Res"[f(frac(1, z))cdotfrac(1, z^2), 0] $

=== 利用留数计算实积分

==== 形如 $integral _0^(2pi )R(costheta ,sintheta )"d"theta$ 的积分

*计算方法*：

+ 令 $z=e^("i"theta )=costheta +"i"sintheta$ ，则 $"d"theta =frac("d"z, "i"z)$ ， $costheta =frac(z^2+1, 2z)$ ， $sintheta =frac(z^2-1, 2"i"z)$ 。
+ $integral _0^(2pi )R(costheta ,sintheta )"d"theta =integral.cont _(|z|=1)R(frac(z^2+1, 2z),frac(z^2-1, 2"i"z))frac(1, "i"z)"d"z=integral.cont _(|z|=1)f(z)"d"z=2pi "i"sum limits_k "Res"[f(z),z_k]$ ，其中 $z_k$ 是 $f(z)$ *在 $|z|=1$ 内*的孤立奇点。

==== 形如 $integral ^(+infinity )_(-infinity )R(x)"d"x$ 的积分

*要求*：

+ $R(x)=frac(P(x), Q(x))$ ，其中 $P(x)$ 和 $Q(x)$ 为多项式，且 $Q(x)$ 无*实零点*。
+ 分母 $Q(x)$ 的次数比分子 $P(x)$ 的次数高 $2$ 或以上。

*计算方法*： $integral ^(+infinity )_(-infinity )R(x)"d"x=2pi "i"sum limits_k"Res"[R(z),z_k]$ ， 其中 $z_k$ 为 $R(z)$在*上半平面*内的孤立奇点。

*例* 求积分 $I=integral _(-infinity )^(+infinity )frac(x^2-x+2, x^4+10x^2+9)"d"x$ .
*解* 首先显然分母零点均为虚数，且分母次数比分子高 $2$ ，故满足条件。

+ 令 $$R(z)=\frac{z^2-z+2}{z^4+10z^2+9}=\frac{z^2-z+2}{(z^2+1)(z^2+9)}$$
则上半平面内有一阶极点 $z_1="i"$ 和 $z_2=3"i"$ 。
+ 则
$ beginaligned
I&=integral _(-infinity )^(+infinity )frac(x^2-x+2, x^4+10x^2+9)"d"x\\
&=2pi "i"sum limits_k"Res"[R(z),z_k] \\
&=2pi "i"("Res"[R(z),"i"]+"Res"[R(z),3"i"])\\
&=2pi "i"(-frac(1+"i", 16)+frac(3-7"i", 48)) = frac(5pi , 12)
endaligned $

==== 形如 $integral ^(+infinity )_(-infinity )R(x)e^("i"ax)"d"x(a>0)$ 的积分

*要求*：

+ $R(x)=frac(P(x), Q(x))$ ，其中 $P(x)$ 和 $Q(x)$ 为多项式，且 $Q(x)$ 无*实零点*。
+ 分母 $Q(x)$ 的次数比分子 $P(x)$ 的次数高 $1$ 或以上。

*计算方法*： $integral ^(+infinity )_(-infinity )R(x)e^("i"ax)"d"x=2pi "i"sum limits_k"Res"[R(z)e^("i"az),z_k]$ ， 其中 $z_k$ 为 $R(z)$在*上半平面*内的孤立奇点。

== Fourier变换

记得上一年的这个时候就对傅里叶变换有所接触了，然而时光荏苒，却一直没能有什么更深的理解，有些惭愧了。

=== Fourier 积分公式

$ f(t) = frac(1, 2pi )integral _(-infinity )^(+infinity )[integral _(-infinity )^(+infinity )f(t)e^(-"i"omega t) "d"t]e^("i"omega t)"d"omega $
这个式子有点奇怪，两边都有 $f(t)$ ，那我要来干嘛呢，这时你先别急，下面拆解一下就有意思了。

=== Fourier 变换

上式中令 $F(omega )=integral _(-infinity )^(+infinity )f(t)e^(-"i"omega t) "d"t$ ，则 $f(t)=frac(1, 2pi )integral _(-infinity )^(+infinity )F(omega )e^("i"omega t)"d"omega$ ，那么这个关于 $omega$ 的函数 $F(omega )$ 就是 $f(t)$ 的傅里叶变换。
这样一来就可以粗略地理解为傅里叶变换就是把*关于时间的函数*转换为*关于频率的函数*，也就是所谓的时域转换为频域。

*例* 求矩形脉冲函数 $f(t)=begincases1, & |t|<= a\\0, & |t|> aendcases$ 的傅里叶变换及傅里叶积分表达式。

*解* 经典例题
$ beginaligned
F(omega )=mathscrF[f(t)]&=integral _(-infinity )^(+infinity )f(t)e^(-"i"omega t) "d"t\\
&=integral _(-a)^(a)e^(-"i"omega t) "d"t\\
&=frac(1, -"i"omega )(e^(-"i"omega a)-e^("i"omega a))\\
&=frac(2, omega )dot frace^(-"i"omega a)-e^("i"omega a)-2"i" \\
&= frac(2, omega )cdotsin aomega 
endaligned $
再作傅里叶逆变换，即得傅里叶积分表达式
$ beginaligned
f(t)=mathscrF^(-1)[F(omega )]&=frac(1, 2pi )integral _(-infinity )^(+infinity )frac(2sin aomega , omega )e^("i"omega t)"d"omega \\
&=frac(1, 2pi )integral _(-infinity )^(+infinity )frac(2sin aomega , omega )cosomega t "d"omega + frac("i", 2pi )integral _(-infinity )^(+infinity )frac(2sin aomega , omega )sinomega t "d"omega \\
&=frac(1, pi )integral _(-infinity )^(+infinity )frac(sin aomega , omega )cosomega t "d"omega \\
&=begincases1, & |t| < a \\ 1/2, & |t| = a \\ 0, & |t| > aendcases
endaligned $
上式中令 $t=0$ ，可得重要积分公式
$ integral _(-infinity )^(+infinity )frac(sin ax, x) "d"x=pi ,quad (a>0) $

=== $delta$ 函数及其 Fourier 变换

我们称满足如下条件的函数为 $delta$ 函数：

+ 当 $t != 0$ 时， $delta (t)=0$ ；
+ $integral _(-infinity )^(+infinity )delta (t)"d"t = 1$
可以看出，这是一个直观上矛盾的函数。书本上也说明了它不是一个经典意义上的函数，而是一个*广义函数*，有兴趣可以另行搜索。

$delta$ 函数有一个性质，就是对任意的连续函数 $f(t)$ ，都有
$ integral _(-infinity )^(+infinity )f(t)delta (t)"d"t = f(0)
$$更一般地，若 $f(t)$ 在 $t=t_0$ 处连续，则 $
\int_{-\infty}^{+\infty}f(t)\delta(t-t_0)\mathrm{d}t = f(t_0)
$ 这是一个很好的**筛选性质**。同时其傅里叶变换也很有意思： $
F(\omega) = \mathscr{F}[\delta(t)] = \int\_{-\infty}^{+\infty}\delta(t)e^{-\mathrm{i}\omega t}\mathrm{d}t = e^{-\mathrm{i}\omega t}|\_{t=0} = 1 \\\\
\delta(t) = \mathscr{F}^{-1}[1] = \frac{1}{2\pi}\int_{-\infty}^{+\infty}e^{\mathrm{i}\omega t}\mathrm{d}\omega
$ ### Fourier 变换的性质

### Fourier 变换的卷积性质

简单来说，就是 $
f_1(t)\*f_2(t) = \int_{-\infty}^{+\infty}f_1(\tau)f_2(t-\tau)\mathrm{d}\tau
$ ## Laplace 变换

### Laplace 变换的概念

**例** 求指数函数 $f(t)=e^(kt) ,k in bb(R)$ 的 Laplace 变换。
**解** $$
beginaligned
F(s)
&=mathscrL[f(t)]\\
&=integral _(0)^(infinity )e^(kt)e^(-st)"d"t\\
&=frac(1, s-k) quad , "Re"(s)>k
endaligned$$

类似地， $f(t)=cos kt$ 的 Laplace 变换为 $F(s)=frac(s, s^2+k^2)$ ， $f(t)=sin kt$ 的 Laplace 变换为 $F(s)=frac(k, s^2+k^2)$ 。

### Laplace 变换的性质 $
\mathscr{L}[f'(t)]=sF(s)-f(0) \\\\
$ 更一般地，有 $
\mathscr{L}[f^{(n)}(t)]=s^nF(s) - s^{n-1}f(0) - s^{n-2}f'(0) - \cdots - f^{(n-1)}(0)
$ ### Laplace 逆变换

**例** 求 $F(s)=frac(1, s^2(s+1))$ 的 Laplace 逆变换。
**解** 函数 $F(s)$满足条件 $lim limits_(s -> 0)F(s)=0$ ，且 $s=0$ 是 $F(s)$ 的二级极点， $s=-1$是 $F(s)$的一级极点，故 $
\begin{aligned}
f(t) = \mathscr{L}^{-1}[F(s)]
&= \mathrm{Res}\left[\frac{e^{st}}{s^s(s+1)},0\right] + \mathrm{Res}\left[\frac{e^{st}}{s^s(s+1)},-1\right] \\\\
&= (t-1) + e^{-t},\quad t > 0
\end{aligned}
$ ### 卷积

### Laplace 变换的应用

**例** 求解微分方程 $y''+omega ^2y(t)=0, y(0)=0, y'(0)=omega $ 。

**解** 令 $Y(s)=mathscrL[y(t)]$ ，对方程两边取 Laplace 变换，得 $
s^2Y(s)-sy(0)-y'(0)+\omega^2Y(s)=0
$ 代入初值条件，得 $
s^2Y(s)-\omega+\omega^2Y(s)=0 \\\\
\Rightarrow Y(s)=\frac{\omega}{s^2+\omega^2}
$ 求逆变换，得 $
\begin{aligned}
y(t)=\mathscr{L}^{-1}\left[\frac{\omega}{s^2+\omega^2}\right] &= \mathrm{Res}\left[\frac{we^{s\mathrm{i}}}{s^2+w^2},w\mathrm{i}\right] + \mathrm{Res}\left[\frac{we^{s\mathrm{i}}}{s^2+w^2},-w\mathrm{i}\right] \\\\
&= \lim_{s\to w\mathrm{i}}\frac{we^{s\mathrm{i}}}{(s^2+w^2)'} + \lim_{s\to -w\mathrm{i}}\frac{we^{s\mathrm{i}}}{(s^2+w^2)'} \\\\
&=\frac{we^w\mathrm{i}t}{2w\mathrm{i}}+\frac{we^{-w\mathrm{i}t}}{-2w\mathrm{i}} \\\\
&=\frac{2\mathrm{i}\sin wt}{2\mathrm{i}}=\sin wt
\end{aligned}
