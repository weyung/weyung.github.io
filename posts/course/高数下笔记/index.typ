#import "../../../config.typ": *

#show: template-post.with(
  title: "高数下笔记",
  description: "挂科了，还是要学好高数啊！",
  tags: ("数学", "高数",),
  category: "Course",
  date: datetime(year: 2022, month: 8, day: 7)
)

= 前言

玩脱了，光顾着搞技术，绩点炸了。

高数 59 ，有人问我说我是不是得罪老师了——但是有没有一种可能，就是。。平时分已经给满了（）

= 笔记正文

== 第六章 多元函数微分学

=== 1. 多元函数

=== 2. 多元函数的极限

=== 3. 多元函数的连续性

=== 4. 偏导数与全微分

*例*（2020-2021 第二学期期末，1）确定实数 $alpha$ 的范围，使下面的函数在 $(0,0)$ 处可微：

$
f(x,y)=cases(
  (x^2+y^2)^alpha sin frac(1, x^2+y^2) & x^2+y^2 != 0,
  0 & x^2+y^2 = 0,
)
$

*解*

$ lim _(x arrow.r 0)frac(f(x,0)-f(0,0), x-0)= lim _(x arrow.r 0)frac(x^(2 alpha) sin frac(1, x^2), x)= lim _(x arrow.r 0)x^(2 alpha -1) sin frac(1, x^2) $

当 $2 alpha -1>0$ 时，极限为 $0$ ，即 $f_x'(0,0)=0$ ，此时类似地，有 $f_y'(0,0)=0$

=== 5. 复合函数与隐函数的微分法

=== 6. 方向导数与梯度

=== 7. 多元函数的微分中值定理与泰勒公式

=== 8. 隐函数存在定理

=== 9. 极值问题

先用 $f_x'=f_y'=0$ 求出驻点，再令

$ A=f_(x x), quad B=f_(x y), quad C=f_(y y) $

仅当 $B^2 < A C$ 时可以确定极值：$A>0$ 时为极小值，$A<0$ 时为极大值。

*例*（2021-2022第二学期期末，4）求多元函数 $f(x,y)=x e^(-frac(x^2+y^2, 2))$ 的极值。

*解* 求一阶偏导：

$
f_x'=e^(-frac(x^2+y^2, 2))(1-x^2), quad
f_y'=-x y e^(-frac(x^2+y^2, 2))
$

令 $f_x'=f_y'=0$，得到 $(-1,0)$ 和 $(1,0)$ 两个驻点。再求二阶偏导：

$
A=f_(x x)=e^(-frac(x^2+y^2, 2))(x^3-3x)
$
$
B=f_(x y)=e^(-frac(x^2+y^2, 2))(-y+x^2 y)
$
$
C=f_(y y)=e^(-frac(x^2+y^2, 2))(-x+x y^2)
$

代入 $(1,0)$ 得到 $A=-2e^(-frac(1, 2))<0$、$B=0$，故 $(1,0)$ 为极大值点；同理，$(-1,0)$ 为极小值点。

== 第七章 重积分

=== 1. 二重积分的概念与性质

=== 2. 二重积分的计算

*例*（2021-2022第二学期期末，2）求 $I= integral _0^1"d"x integral _0^(sqrt(1-x^2))(x^2+y^2)"d"y$

*解* 作极坐标变换 $x=r cos theta ,y=r sin theta$，则

$ I = integral _0^(frac( pi , 4))"d" theta integral _0^1 r dot.op r"d"r = frac( pi , 12) $

*例*（2017-2018第二学期期末，1）计算二重积分 $integral.double _D frac(|y|, x^2+y^2)"d"x"d"y$，其中 $D$ 为圆环区域 $1 <= x^2+y^2 <= 4$。

*解* 作极坐标变换，有

$
I = integral _0^(2 pi ) "d"theta integral _1^2
  frac(|r sin theta|, r^2) dot.op r "d"r
$
$
I = integral _0^(2 pi ) |sin theta| "d"theta integral _1^2 "d"r
$
$
I = 4 integral _0^(frac(pi, 2)) sin theta "d"theta integral _1^2 "d"r = 4
$

=== 3. 三重积分的概念与计算

=== 4. 重积分的应用举例

曲面 $S$ 由下面的参数方程给出时：

$ x=x(u,v), quad y=y(u,v), quad z=z(u,v), quad (u,v) in D' $

可计算

$
E = x_u^2+y_u^2+z_u^2
$
$
F = x_u x_v+y_u y_v+z_u z_v
$
$
G = x_v^2+y_v^2+z_v^2
$

从而

$ S = integral.double _(D')sqrt(E G-F^2)"d"u"d"v $

== 第八章 曲线积分与曲面积分

=== 1. 第一型曲线积分（对弧长的曲线积分）

这个非常地简单直观，就是求一条曲线（如二次函数的某一段）的长度。

平面曲线求法：

$ integral _L f(x,y) d s= integral _ alpha ^ beta f[x(t),y(t)]sqrt([x'(t)]^2+[y'(t)]^2) d t $

也可以写成：

$ integral _L f(x,y) d s= integral _ alpha ^ beta f[x,y(x)]sqrt(1+[y'(x)]^2) d x $

空间曲线类似：

$ integral _L f(x,y,z) d s= integral _ alpha ^ beta f[x(t),y(t),z(t)]sqrt([x'(t)]^2+[y'(t)]^2+[z'(t)]^2) d t $

=== 2. 第二型曲线积分（对坐标的曲线积分）

这个看起来就不那么地直观，其物理背景是求变力在曲线上做功，大概想象一下子。

计算方法：

$ integral _(accent(A B, ⌢)) P(x,y) d x= integral _ alpha ^ beta P[x(t),y(t)]x'(t) d t $

$ integral _(accent(A B, ⌢)) Q(x,y) d y= integral _ alpha ^ beta Q[x(t),y(t)]y'(t) d t $

两类曲线积分关系：

$ integral _L P d x+Q d y= integral _L (P cos alpha +Q cos beta ) d s $

空间曲线对应为：

$ integral _ Gamma P d x+Q d y+R d z= integral _L (P cos alpha +Q cos beta +R cos gamma ) d s $

=== 3. 格林公式

就一道式子：

$ ∮_L P d x+Q d y=∬ _D ( frac( partial Q , partial x )- frac( partial P , partial y )) d x d y $

条件是函数 $P$ 和 $Q$ 在平面区域 $D$ 上有连续的偏导数 #strike[，这个条件一般不管，] 主要是*边界曲线 $L$ 闭合*就行。

格林公式可以将*第二类曲线积分*化为简单的二重积分，非常地不错。

#quote[
PS:以下这些符号的 Latex 支持不是很好，直接用字符了。

$ ∮ ∯ ∰ ∱ ∲ ∳ $
]

*例*（2020-2021第二学期期末，2）计算曲线积分 $∮_L (x y^2- sin y)"d"y-( cos x+x^2 y)"d"x$ ，其中 $L$ 为圆周 $x^2+y^2=4$ ，积分方向为沿 $L$ 逆时针方向。

*解* $L$ 为闭合曲线，且 $P,Q$ 在 $L$ 围成的 $D$ 上偏导也连续，所以可以用格林公式：

$
I = integral.double _D[y^2-(-x^2)]"d"x"d"y
$
$
I = integral _0^(2 pi )"d" theta integral _0^2r^2 dot.op r"d"r
$
$ I=8 pi $

=== 4. 第一型曲面积分

和第一型曲线积分一样直观，就是求一个曲面的面积。

计算方法：

$ integral.double _( Sigma ) f(x,y,z) "d"S= integral.double _(D_(x y)) f[x,y,z(x,y)]sqrt(1+(frac( partial z, partial x))^2+(frac( partial z, partial y))^2)"d"x"d"y $

=== 5. 第二型曲面积分

计算方法：

$ integral.double _( Sigma ) R(x,y,z) "d"S= integral.double _(D_(x y)) R[x,y,z(x,y)]"d"x"d"y $

两类曲面积分关系：

$ integral.double _ Sigma P"d"y"d"z+Q"d"x"d"z+R"d"x"d"y= integral.double _ Sigma (P cos alpha +Q cos beta +R cos gamma )"d"S $

=== 6. 高斯公式与斯托克斯公式

*高斯公式*：

$
∯ _ Sigma P"d"y"d"z+Q"d"z"d"x+R"d"x"d"y
= integral.triple _ Omega div bold(F) "d"V
$

其中

$
div bold(F)=frac(partial P, partial x)+frac(partial Q, partial y)+frac(partial R, partial z)
$

也可以写成

$
∯ _ Sigma bold(F) dot.op bold(n) "d"S
= integral.triple _ Omega div bold(F) "d"V
$
*例*（2021-2022第二学期期末，3）计算曲面积分 $∯ _ Sigma (x-z)"d"y"d"z+z"d"x"d"y$ ，其中 $Sigma$ 是由 $z=x^2+2y^2$ 与 $z=1$ 所围成立体表面的外侧。

*解* $Sigma$ 是封闭曲面，直接上高斯公式，有

$ I= integral.triple _ Omega (1+1)"d"x"d"y"d"z=2 integral.triple _ Omega "d"V $

作柱面坐标变换 $x=r cos theta ,y=frac(r sin theta , sqrt(2))$ ，得

$ I= integral _0^(2 pi )"d" theta integral _0^1"d"r integral _0^1frac(r, sqrt(2)) d z=frac( pi , sqrt(2)) $

#quote[
直角坐标与柱面坐标关系：

$
x=r cos theta
$
$
y=r sin theta
$
$
z=z
$
]

此时 $"d"V=r"d"r"d" theta "d"z$

直角坐标与球面坐标关系：

$
x=r sin phi.alt cos theta
$
$
y=r sin phi.alt sin theta
$
$
z=r cos phi.alt
$

此时 $"d"V=r^2 sin phi.alt "d"r"d" theta "d" phi.alt$

*斯托克斯公式*：

$
∮_L P"d"x+Q"d"y+R"d"z
= integral.double _ Sigma D(P,Q,R) "d"S
$

其中

$
D(P,Q,R)=mat(
  delim: "|",
  cos alpha, cos beta, cos gamma;
  frac(partial, partial x), frac(partial, partial y), frac(partial, partial z);
  P, Q, R,
)
$

== 第九章 常微分方程

=== 1. 基本概念

所谓常微分方程，就是区别于偏微分方程，未知函数是*一元函数*，而不是多元。

常微分方程的阶数即肉眼可见的导数的最高阶，如 $y'''+2(y'')^3+y^2+x^5$ 就是三阶常微分方程。

*通解*的概念：$n$ 阶常微分方程有解 $y= phi.alt (x;C_1, dots.c ,C_n)$ ，其中 $C_1, dots.c ,C_n$ 是 $n$ 个独立的任意常数，则称其为方程的一个通解；相对的，就有特解的概念，即方程的任何一个不包含任意常数的解。用数学语言表达独立性，有雅可比行列式不为零，即

$ frac(D( phi.alt , phi.alt ', dots.c , phi.alt ^(n-1)), D(C_1,C_2, dots.c ,C_n)) != 0 $

举个例子，经典方程 $y''+y=0$ 有解 $y=C_1 sin x+C_2 cos x$ ，则雅可比行列式为

$ frac(D(y,y'), D(C_1,C_2))=
mat(delim: "|",
sin x, cos x;
cos x, -sin x
)
=-1 != 0 $

可能你会问这个雅可比行列式具体怎么出來的，其实第一行就是 $y$ 分别对 $C_1$ 和 $C_2$ 求导，第二行是 $y'$ 对 $C_1$ 和 $C_2$ 求导。

故 $C_1,C_2$ 是两个独立的任意常数，进而 $y=C_1 sin x+C_2 cos x$ 是方程的通解。

=== 2. 初等积分法

==== 2.1 变量分离的方程

==== 2.2 可化为变量分离的几类方程

==== 2.3 一阶线性微分方程

形如

$ frac("d"y, "d"x)+P(x)y=Q(x) $

的一阶微分方程就叫一阶线性微分方程。

一般套公式就行，若 $Q(x) equiv 0$ ，则为齐次方程，直接积分有通解 $y=C"e"^(- integral P(x)"d"x)$ ；若为非齐次方程则用*常数变易法*求得通解

$ y="e"^(- integral P(x)"d"x)[ integral Q(x)"e"^( integral P(x)"d"x) d x+C] $

然后还有*贝努里方程*（当然贝努利方程也是它，音译嘛）长这样：

$ frac("d"y, "d"x)+P(x)y=Q(x)y^n (n != 0,1) $

作变量代换 $z=y^(1-n)$ ，可化为一阶线性方程

$ frac("d"z, "d"x)+(1-n)P(x)z=(1-n)Q(x) $

==== 2.4 全微分方程与积分因子

*例*（2021-2022第二学期期末，4）求微分方程 $x"d"y+(y+x^2)"d"x=0$ 的通解。

*解* $frac( partial P, partial y)=1=frac( partial Q, partial x)$，且它们在全平面上连续，故方程为全微分方程。下求原函数 $u(x,y)$ ，由 $frac( partial u, partial x)=P(x,y)=y+x^2$ ，对 $x$ 积分得

$ u(x,y)=x y+frac(x^3, 3)+ phi.alt (y) $

上式对 $y$ 求偏导得

$ frac( partial u, partial y)=x+ phi.alt '(y) $

另一方面，

$ frac( partial u, partial y)=Q(x,y)=x $

比较上两式得 $phi.alt '(y)=0$ ，因而 $phi.alt (y)=0$（这里省略积分常数，不影响后面的通积分表达式），故原函数为 $u(x,y)=x y+frac(x^3, 3)$ ，故方程的通解为

$ x y+frac(x^3, 3)=C $

其中 $C$ 为任意常数。

#quote[
微分方程的通解也叫通积分
]

==== 2.5 可降阶的二阶微分方程

*例*（2021-2022第二学期期末，5）求微分方程 $y''=y' dot.op y$ 的通解。

*解* 方程中不显含变量 $x$ ，令 $p=y'$ ，并将 $y$ 看作自变量，有 $y''=p frac("d"p, "d"y)$ ，代入有

$ p frac("d"p, "d"y)=p dot.op y $

若 $p=y'=0$ ，则通解为 $y=C$ ，若 $p != 0$ ，则有

$
frac("d"p, "d"y)=y
$
$
integral "d"p=integral y"d"y
$
$
p=frac(1, 2)y^2+C_1
$

即 $frac("d"y, "d"x)=frac(1, 2)y^2+C_1$ ，再次分离分量，有

$
frac("d"y, "d"x)=frac(1, 2)y^2+C_1
$
$
integral frac(2, y^2)"d"y=integral "d"x + C_2
$
$
-frac(2, y)=x+C_3
$
$
y=-frac(2, x)+C
$

#quote[
这里面的常量 $C$ 变得我也很迷糊，但是结果代进去是对的，就先这样吧（）
]

*例*（2020-2021第二学期期末，5）求微分方程 $frac("d"^2y, "d"x^2)=(frac("d"y, "d"x))^3+frac("d"y, "d"x)$ 的通解。

*解* 令 $p=y'$ ，有 $y''=p frac("d"p, "d"y)$ ，代入有

$ p frac("d"p, "d"y)=(p^3+p) $

$ frac(1, p^2+p)"d"p="d"y $

$ arctan p=y+C_1 $

即有 $frac("d"y, "d"x)=p= tan (y+C_1)$ ，再次分离分量，有

$ frac("d"y, tan (y+C_1))="d"x $

$ ln sin (y+C_1)=x+C_2 $

最终得出 $y= arcsin e^(x+C_2)-C_1$

=== 3. 微分方程解的存在唯一性定理

=== 4. 高阶线性微分方程

=== 5. 二阶线性常系数微分方程

#table(
  columns: (1fr, 1.8fr),
  table.header([特征根], [通解形式]),
  [两相异实根 $lambda_1, lambda_2$],
  [$C_1 e^(lambda_1 x)+C_2 e^(lambda_2 x)$],
  [二重根 $lambda_1$],
  [$(C_1+C_2 x)e^(lambda_1 x)$],
  [共轭复根 $lambda_(1,2)=alpha plus.minus "i" beta$],
  [$e^(alpha x)(C_1 cos beta x+C_2 sin beta x)$],
)

#table(
  columns: (1.15fr, 1fr, 1.8fr),
  table.header([$f(x)$ 的形式], [条件], [特解的形式]),
  [$P_n(x)$],
  [$0$ 不是、是单、是重特征根],
  [$Q_n(x)$、$x Q_n(x)$、$x^2 Q_n(x)$],
  [$a e^(alpha x)$],
  [$alpha$ 不是、是单、是重特征根],
  [$A e^(alpha x)$、$A x e^(alpha x)$、$A x^2 e^(alpha x)$],
  [$a cos beta x+b sin beta x$],
  [$plus.minus "i" beta$ 不是、是特征根],
  [$A cos beta x+B sin beta x$；$x(A cos beta x+B sin beta x)$],
  [$P_n(x)e^(alpha x)$],
  [$alpha$ 不是、是单、是重特征根],
  [$Q_n(x)e^(alpha x)$、$x Q_n(x)e^(alpha x)$、$x^2 Q_n(x)e^(alpha x)$],
  [$P_n(x)e^(alpha x)(a cos beta x+b sin beta x)$],
  [$alpha plus.minus "i" beta$ 不是、是特征根],
  [$e^(alpha x)(Q_n(x) cos beta x+R_n(x) sin beta x)$；$x e^(alpha x)(Q_n(x) cos beta x+R_n(x) sin beta x)$],
)

咋一看很多，其实挺有规律，比如多一个根就多乘一个 $x$ ，原来的系数变成待定的。

*例*（2021-2022第二学期期末，6）求微分方程 $y''+y=e^(3x)(x+2)$ 的通解。

*解* 先求对应齐次微分方程 $y''+y=0$ 的通解，特征方程 $lambda ^2+1=0$ 的特征根 $lambda _(1,2)= plus.minus "i"$ ，故通解形式为

$ y(x)=e^(a x)(C_1 cos beta x+C_2 sin beta x)=C_1 cos x+C_2 sin x $

其中 $C_1,C_2$ 为任意常数

再用待定系数法求特解，”3”不是特征根，故设方程有特解 $y=(A x+B)e^(3x)$ ，则

$
y'=A e^(3x)+3(A x+B)e^(3x)
$
$
y''=3A e^(3x)+3A e^(3x)+9(A x+B)e^(3x)=(9A x+6A+9B)e^(3x)
$

回代得

$ y''+y=(10A x+6A+10B)e^(3x)=e^(3x)(x+2) $

解得 $A=frac(1, 10), B=frac(7, 50)$ ，故特解为 $y=(frac(1, 10)x+frac(7, 50))e^(3x)$ ，与齐次方程通解相加，得出所求非齐次方程通解为

$ y(x)=C_1 cos x+C_2 sin x+(frac(1, 10)x+frac(7, 50))e^(3x) $

其中 $C_1,C_2$ 为任意常数。

*例*（2020-2021第二学期期末，6）求微分方程 $frac("d"^2y, "d"x^2)+y=e^x+ cos x$ 的通解。

*解* 特征方程 $lambda ^2+1=0$ 的特征根 $lambda _(1,2)= plus.minus "i"$ ，故齐次方程通解形式为

$ y(x)=e^(a x)(C_1 cos beta x+C_2 sin beta x)=C_1 cos x+C_2 sin x $

这个方程的非齐次项由两项组成，就先分别求两项的特解，再相加，就是原方程的特解。

对方程 $y''+y=e^x$ 不难求得特解 $y=frac(1, 2)e^x$，方程 $y''+y=cos x$ 的特解 $y=frac(1, 2)x sin x$，故原方程的特解为

$ y=frac(1, 2)(e^x+x sin x) $

与齐次方程通解相加，得出所求非齐次方程通解为

$ y(x)=C_1 cos x+C_2 sin x+frac(1, 2)(e^x+x sin x) $

=== 6. 用常数变易法求解二阶线性非齐次方程与欧拉方程的解法

=== 7. 常系数线性微分方程组

== 第十章 无穷级数

=== 1. 柯西收敛原理与数项级数的概念

=== 2. 正项级数的收敛判别法

- *比较审敛法*：比收敛级数小的级数收敛，比发散级数大的级数发散。
- *比值审敛法*：$lim _(n -> infinity) frac(u_(n+1), u_n)$ 小于 $1$ 时收敛，大于 $1$ 时发散，等于 $1$ 时敛散性不定。
- *根值审敛法*：$lim _(n -> infinity) root(n, u_n)$ 小于 $1$ 时收敛，大于 $1$ 时发散，等于 $1$ 时敛散性不定。
- *对数审敛法*：通过对数变换，将问题化为更易判断的极限或比较问题。

*例*（2021-2022第二学期期末，10-1）判断数项级数 $sum _(n=1)^( infinity )3^n sin (frac( pi , 4^n))$ 的敛散性。

*解* 放缩一下再比较判别法

$ sum _(n=1)^( infinity )3^n sin (frac( pi , 4^n))< sum _(n=1)^( infinity )3^n(frac( pi , 4^n))= pi sum _(n=1)^( infinity )(frac(3, 4))^n $

由于 $sum _(n=1)^( infinity )(frac(3, 4))^n$ 收敛，故原级数收敛。

=== 3. 任意项级数

*莱布尼茨判别法* 若交错级数满足下列条件：

+ $u_n gt.eq u_(n+1)$；
+ $lim _(n arrow.r infinity) u_n = 0$。

则级数收敛。

*狄利克雷判别法* 考虑级数

$ sum _(k=1)^( infinity )a_k b_k $

若序列 $a_k$ 单调且 $lim _(k arrow.r infinity)a_k=0$，又级数 $sum _(k=1)^(infinity)b_k$ 的部分和序列有界，则级数 $sum _(k=1)^(infinity)a_k b_k$ 收敛。

*例*（2021-2022第二学期期末，10-2）判断数项级数 $sum _(n=2)^( infinity )frac( cos (2n), ln n)$ 的敛散性。

*解* 取 $a_k=frac(1, ln k)$，易证得 $a_k$ 单调且 $lim _(k arrow.r infinity)a_k=0$，下证级数 $sum _(k=2)^(infinity) cos (2k)$ 的部分和序列有界：

$ sum _(k=2)^n cos(2k)=frac(sin(n-1) cos(n+2), sin 1) $

因此

$ |sum _(k=2)^n cos(2k)| lt.eq frac(1, |sin 1|) $

故级数 $sum _(n=2)^( infinity )frac( cos (2n), ln n)$ 收敛。

#quote[
*积化和差公式*

$ sin alpha cos beta = frac(sin(alpha+beta)+sin(alpha-beta), 2) $
$ cos alpha sin beta = frac(sin(alpha+beta)-sin(alpha-beta), 2) $
$ cos alpha cos beta = frac(cos(alpha+beta)+cos(alpha-beta), 2) $
$ sin alpha sin beta = frac(cos(alpha-beta)-cos(alpha+beta), 2) $
]

*阿贝尔判别法*

+ 无穷数列 $a_k$ 单调有界；
+ 级数 $sum _(k=1)^infinity b_k$ 收敛。

则级数 $sum _(k=1)^ infinity a_k b_k$ 收敛。

=== 4. 函数项级数

==== 4.1 函数序列及函数项级数的一致收敛性

==== 4.2 函数项级数一致收敛的必要条件与判别法

*强级数判别法* 若函数项级数 $sum _(n=1)^ infinity u_n(x)$ 的一般项满足：

$ |u_n(x)| lt.eq a_n, quad forall x in X,n=1,2, dots.c , $

且正项级数 $sum _(n=1)^ infinity a_n$ 收敛，则该函数项级数在 $X$ 上一致收敛。

*狄利克雷判别法* 与数项级数的狄利克雷判别法类似。

+ 在 $X$ 中任意取定一个 $x$，数列 $a_n(x)$ 对 $n$ 单调，且函数序列 $a_n(x)$ 在 $X$ 上一致收敛于 $0$；
+ 函数项级数 $sum _(n=1)^infinity b_n(x)$ 的部分和序列 $B_n(x)$ 在 $X$ 上一致有界。

则 $sum _(n=1)^ infinity a_n(x)b_n(x)$ 在 $X$ 上一致收敛。

*阿贝尔判别法* 与数项级数的阿贝尔判别法类似。

+ 在 $X$ 中任意取定一个 $x$，数列 $a_n(x)$ 单调，且函数序列 $a_n(x)$ 在 $X$ 上一致有界；
+ 级数 $sum _(n=1)^infinity b_n(x)$ 在 $X$ 上一致收敛。

则级数 $sum _(n=1)^ infinity a_n(x)b_n(x)$ 在 $X$ 上一致收敛。

==== 4.3 一致收敛级数的性质

*和函数的连续性* 设函数项级数 $sum _(n=1)^ infinity u_n(x)$ 在 $[a,b]$ 上一致收敛，且其每一项 $u_n(x)$ 在 $[a,b]$ 上都连续，则其和函数 $S(x)= sum _(n=1)^ infinity u_n(x)$ 在 $[a,b]$ 上也连续。

*例*（2021-2022 第二学期期末，11）考虑函数项级数 $sum _(n=2)^(infinity)frac(1, n^2 sqrt(x))$，证明：

+ 级数在 $(0,1)$ 上收敛；
+ 级数在 $(0,1)$ 上不一致收敛；
+ 级数的和函数 $S(x)$ 在 $(0,1)$ 上连续。

*解*

+ 固定任意 $x in (0,1)$，原级数是常数 $frac(1, sqrt(x))$ 与收敛级数 $sum_(n=2)^infinity frac(1,n^2)$ 的乘积，故收敛。
+ 取点列 $x_n=frac(1,n^4) in (0,1)$，有 $u_n(x_n)=1$，所以一般项不一致收敛于 $0$，原级数不一致收敛。
+ 对任意闭区间 $[a,b] subset (0,1)$，有 $frac(1,n^2 sqrt(x)) lt.eq frac(1,n^2 sqrt(a))$，由强级数判别法可知级数在 $[a,b]$ 上一致收敛，因此和函数在 $(0,1)$ 上连续。

=== 5. 幂级数

幂级数是*函数项级数的一种*，长这样：

$ a_0+a_1(x-x_0)+a_2(x-x_0)^2+ dots.c +a_n(x-x_0)^n+ dots.c $

==== 5.1 幂级数的收敛半径

$ lim _(n arrow.r infinity )|frac(a_(n+1), a_(n))|=l $

那么级数 $sum ^n_(n=0) a_n x^n$ 的*收敛半径* $R=1/l$ ，当然直接反着除直接出也行。

*收敛区间*就是 $(-R,R)$ ，*收敛域*就根据端点的收敛情况再修正下区间闭不闭合。

*例*（2021-2022第二学期期末，8）求幂级数 $sum ^ infinity _(n=0)frac(1, n+1)x^n$ 的收敛半径与和函数。

*解*

$ lim _(n arrow.r infinity )|frac(a_n, a_(n+1))|= lim _(n arrow.r infinity )|frac(n, n+1)|=1 $

故收敛半径 $R=1$ ，收敛区间 $(-1,1)$ 。

然后讨论两个端点：当 $x=1$ 时，原级数发散；当 $x=-1$ 时，原级数收敛，故收敛域为 $[-1,1)$。

设和函数 $S(x)= sum ^ infinity _(n=0)frac(1, n+1)x^n$ ，则两边乘 $x$ 有 $x S(x)= sum ^ infinity _(n=0)frac(1, n+1)x^(n+1)$ ，两边求导有

$ [x S(x)]'= sum ^ infinity _(n=0)x^n=frac(1, 1-x) $

再两边求积，有

$ x S(x)= integral ^x_0frac(1, 1-x)"d"x=- ln (1-x), x in [-1,1) $

故当 $x != 0$ 时，$S(x)=-frac(1, x) ln (1-x)$ ；当 $x=0$ 时，肉眼可见 $S(x)=1$ 。

#quote[
这里有个小 trick ，就是*幂级数里认定 $0^0=1$* ，至于为什么是这样，网上众说纷纭，读者可自行查阅。
]

==== 5.2 幂级数的性质

和函数项级数一样，可以逐项求积，也可以逐项求导。

=== 6. 泰勒级数

求函数在 $x=k$ 处的泰勒展开式就作 $t=x-k$ 变换，然后求出来的式子再代回去就行了。

记一下常用的几条泰勒展开式：

$ frac(1, 1-x)=sum_(n=0)^infinity x^n, quad |x|<1 $
$ e^x=sum_(n=0)^infinity frac(x^n, n!) $
$ sin x=sum_(n=0)^infinity (-1)^n frac(x^(2n+1), (2n+1)!) $
$ cos x=sum_(n=0)^infinity (-1)^n frac(x^(2n), (2n)!) $
$ arctan x=sum_(n=0)^infinity (-1)^n frac(x^(2n+1), 2n+1), quad |x| lt.eq 1 $
$ ln(1+x)=sum_(n=1)^infinity (-1)^(n-1) frac(x^n, n), quad -1 < x lt.eq 1 $
$ (1+x)^alpha=sum_(n=0)^infinity binom(alpha, n) x^n, quad |x|<1 $

*例*（2021-2022第二学期期末，10）求函数 $y=frac(x, 4+x^2)$ 在 $x=0$ 处的泰勒级数，并指出其收敛域。

*解* $y=frac(x, 4) dot.op frac(1, 1+(frac(x, 2))^2)$，右边显然就是 $arctan x$ 导数的形式了，故我们由 $arctan x$ 的泰勒展开式逐项求导有

$ frac(1, 1+x^2)=( arctan x)'=1-x^2+x^4-x^6+ dots.c +(-1)^(n)x^(2n)+ dots.c $

变形得

$ frac(1, 1+(frac(x, 2))^2)=1-frac(x^2, 4)+frac(x^4, 16)-frac(x^6, 64)+ dots.c +(-1)^(n) frac(x^(2n), 2^(2n))+ dots.c $

最后代入 $y=frac(x, 4) dot.op frac(1, 1+(frac(x, 2))^2)$，有

$ y=frac(x, 4)-frac(x^3, 16)+frac(x^5, 64)-frac(x^7, 256)+ dots.c +(-1)^n frac(x^(2n+1), 2^(2n+2))+ dots.c $

那么级数形式为

$ y= sum ^ infinity _(n=0)frac((-1)^n, 4^(n+1))x^(2n+1) $

令 $t=x^2$，对应幂级数关于 $t$ 的收敛半径为 $4$，因此原级数满足 $|x|<2$。

当 $x=plus.minus 2$ 时，一般项不趋于 $0$，故两个端点都发散，最终收敛域为 $(-2,2)$。
