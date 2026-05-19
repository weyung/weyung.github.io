#import "../../../config.typ": *

#show: template-post.with(
  title: "材料力学笔记",
  description: "莫名其妙考了个第一，来还个愿",
  tags: ("材料力学",),
  category: "Course",
  date: datetime(year: 2023, month: 1, day: 24)
)

最近买了台二手服务器，折腾了一些集群、容器、虚拟化之类的东西，比较偏操作也没啥好记的，就很长时间没更了。

这里大致记一下概念，捋一下思路。

== 绪论

=== 材料力学的任务

使材料满足三个要求：*强度*、*刚度*、*稳定性*。

=== 变形固体的基本假设

三个假设：*连续性*、*均匀性*、*各向同性*。

=== 变形与应变

应变 $epsilon.alt$ 和切应变 $gamma$ 是度量一点处变形程度的两个基本量，量纲为一。

=== 杆件变形的基本形式

拉伸或压缩、剪切、弯曲、扭转。

== 拉伸、压缩与剪切

=== 直杆轴向拉伸或压缩时斜截面上的应力

拉（压）杆的破坏并不总是沿横截面发生，有时沿斜截面发生。

设与横截面成 $alpha$ 角的斜截面 $k-k$ 的面积为 $A_ alpha$，横截面的面积为 $A$，则
$ A_ alpha = frac(A, cos alpha ) $

把应力 $p_ alpha$ 分解成垂直于斜截面的正应力 $sigma _ alpha$ 和沿斜截面的剪应力 $tau _ alpha$，则
$ sigma _ alpha = p_ alpha cos alpha = sigma cos ^2 alpha \\
 tau _ alpha = p_ alpha sin alpha = sigma cos alpha sin alpha = frac( sigma , 2) sin 2 alpha $

当 $alpha = 0$ 时，$sigma _ alpha$ 达到最大值，即
$ sigma _( alpha "max") = sigma $

=== 材料拉伸时的力学性能

低碳钢的力学性能大致如下：

+ 弹性阶段：应力 $sigma$ 与应变 $epsilon.alt$ 成正比，即有 $sigma = E epsilon.alt$ ，$E$ 为*弹性模量*。直线最高点对应的应力 $sigma _"p"$ 称为*比例极限*，超过这个比例极限后，还有一个*弹性极限*，这两点间虽然不是直线，但松开后变形还是可以*完全消失*的，但两点非常接近，所以实际上不作严格区分。
+ 屈服阶段：一段小锯齿，应变*明显增加*，应力*先下降再小波动*，先下降的那个最低点为屈服阶段或屈服强度，记作 $sigma _"s"$ 。
+ 强化阶段：恢复抵抗变形能力，最高点对应应力 $sigma _"b"$ 为*强度极限*。
+ 局部变形阶段：过强度极限后出现缩颈

铸铁在较小拉应力下就被拉断，没有屈服和缩颈现象，拉断前的应变也小，是典型的脆性材料。

=== 材料压缩时的力学性能

#quote[
什么？这不是饼干，这是一个压缩毛巾啊......（滑稽）
]

低碳钢压缩时的弹性模量 $E$ 和屈服极限 $sigma _"s"$ 都和拉伸时大致相同，之后越压越扁，也越来越难压，所以得不到压缩时的强度极限。

铸铁仍在较小变形下突然破坏，破坏断面法线与轴线大致成 45° - 55° 角。

=== 失效、安全因数和强度计算

对塑性材料，$[ sigma ] = frac( sigma _"s", n_"s")$；对脆性材料，$[ sigma ] = frac( sigma _"b", n_"b")$。其中 $n_"s"$ 和 $n_"b"$ 称为*安全系数*，有
$ sigma = frac(F_"N", A) "leqslant" [ sigma ] $

=== 轴向拉伸或压缩时的变形

$ Delta l = frac(F_"N"l, EA) = frac(Fl, EA) $

可以看出，对长度相同、受力相等的杆件，$EA$ 越大变形 $Delta l$ 就越小，所以 $EA$ 越大的材料越强，称为杆件的抗拉（压）*刚度*。

试验表明，应力不超过比例极限时横向应变 $epsilon.alt '$ 与轴向应变 $epsilon.alt$ 之比是一个常数，即
$ mu = -frac( epsilon.alt ', epsilon.alt ) $
$mu$ 称为横向变形因数或*泊松比*。之所以有个负号，是因为一般材料都是伸长时横向缩小，压缩时横向增大。

=== 轴向拉伸或压缩时的应变能

杆件拉伸时，有 $W = frac(1, 2)F Delta l$，忽略动能、热能等变化，杆件就只存到了应变能 $V_ epsilon.alt = W = frac(1, 2)F Delta l = frac(F^2l, 2EA)$，比能 $v_ epsilon.alt = frac(1, 2) sigma epsilon.alt$。

*能量法*解题时需要计算应变能。

=== 拉伸、压缩超静定问题

理论力学默认材料都是刚体，没法解决超静定问题，但实际上材料总是会变形的。

=== 温度应力和装配应力

温度变化为 $Delta T$ 时，杆件变形为
$ Delta l_T = alpha _l Delta T dot.op l $
式中 $alpha _l$ 为材料的*线胀系数*。

=== 剪切和挤压的实用计算

$ tau = frac(F_"S", A) "leqslant" [ tau ] $

== 扭转

=== 外力偶矩的计算

由
$ 2 pi times frac(n, 60) times M_"e" = P times 1000 $
得出计算外力偶矩 $M_"e"$ 的公式为
$ M_"e"_("N dot.op m") = 9549 "frac"{P_"kW"}{n_"r/min"} $

=== 纯剪切

对各向同性材料，三个弹性常数 $E,G, mu$ 之间存在下列关系：
$ G = frac(E, 2(1+ mu )) $

=== 圆轴扭转时的应力

最大切应力
$ tau _"max" = frac(T, W_"t") $
式中 $W_"t"=I_p/R$ 为*抗扭(twist)截面系数*。
圆截面的抗扭截面系数为
$ W_"t" = frac( pi D^3, 16) $
空心圆截面的抗扭截面系数为
$ W_"t" = frac( pi , 16D)(D^4 - d^4) = frac( pi D^3, 16)(1 - alpha ^4) $

=== 圆轴扭转时的变形

距离为 $l$ 的两个横截面之间的*相对转角*为
$ phi.alt = frac(Tl, G I_"p") $
$phi.alt$ 的变化率 $phi.alt '$ 为*单位长度扭转角*，单位为 rad/m，即
$ phi.alt '_"max" = frac(T, G I_"p") "leqslant" [ phi.alt '] $
式中 $I_"p"$ 为横截面对圆心 $O$ 点的极惯性矩，即
$ I_"p" = integral _A rho ^2 "d"A $
圆截面的 $I_"p" = frac( pi D^4, 32)$，空心圆截面的 $I_"p" = frac( pi D^4, 32)(1 - alpha ^4)$。

=== 圆柱形密圈螺旋弹簧的应力和变形

弹簧最大切应力
$ tau _"max" = (frac(4c-1, 4c-4)+frac(0.615, c))frac(8FD, pi d^3) = kfrac(8FD, pi d^3) $
式中 $c=frac(D, d)$ 为*弹簧指数*，$k$ 为曲度系数。

==== 刚度系数

$ C = frac(Gd^4, 8D^3n) = frac(Gd^4, 64R^3n) $
代表弹簧抵抗变形的能力。
变形 $lambda = frac(F, C)$ 。

=== 非圆截面杆扭转的概念

$ tau _"max" = frac(T, alpha hb^2) $

== 弯曲内力

=== 弯曲的概念和实例

以*弯曲*变形为主的杆件习惯上称为*梁*。

=== 剪力和弯矩

符号规定：

- 剪力：截面 $m-m$ 的左段对右段向上相对错动时，截面 $m-m$ 上的剪力规定为正；反之为负。
- 弯矩：截面 $m-m$ 处弯曲变形凸向下时，截面 $m-m$ 上的弯矩规定为正；反之为负。

计算剪力和弯矩时注意考虑*支座反力*。
弯矩方程对距离求导为剪力方程。

=== 平面曲杆的弯曲内力

分析时取圆心角为 $phi.alt$ 的横截面 $m-m$ 将曲杆分成两部分，然后列平衡方程。

符号规定：

- 引起*拉伸*变形的轴力 $F_"N"$ 为正
- 使轴线*曲率增加*的弯矩 $M$ 为正
- 以剪力 $F_"S"$ 对所考虑的一段曲杆内任一点取矩，若力矩为*顺时针*方向，则剪力 $F_"S"$ 为正

== 弯曲应力

=== 概述

弯矩 $M$ 只与横截面上的正应力 $sigma$ 有关，剪力 $F_"S"$ 只与横截面上的切应力 $tau$ 有关。

梁中间段上剪力为零，弯矩为常量的情况称为*纯弯曲*。

梁发生弯曲变形时长度不变的纤维层称为中性层，中性层与横截面的交线称为*中性轴*。

=== 横力弯曲时的正应力

工程实际中觉的弯曲问题多为*横力弯曲*，此时梁的横截面上不仅有*正应力*而且有*切应力*。

一般情况下，最大正应力 $sigma _"max"$ 发生于弯矩最大的截面上，且离中性轴最远处，即
$ sigma _"max" = frac(M_"max"y_"max", I_z) $
引入记号
$ W = frac(I_z, y_"max") $
则有
$ sigma _"max" = frac(M_"max", W) $
$W$ 称为*抗弯截面系数*，与截面的几何形状有关，单位为 $"m"^3$ 。

若截面是高为 $h$、宽为 $b$ 的矩形，则
$ W = frac(I_z, h/2) = frac(bh^3/12, h/2) = frac(bh^2, 6) $
若截面是直径为 $d$ 的圆形，则
$ W = frac(I_z, d/2) = frac( pi d^4/64, d/2) = frac( pi d^3, 32) $
类似地，空心圆形截面的抗弯截面系数为
$ W = frac( pi d^3(1- alpha ^4), 32) $
弯曲正应力的强度条件为
$ sigma _"max" = frac(M_"max", W) "leqslant" [ sigma ] $

=== 弯曲切应力

$ S_z^* = integral _(A_1)y_1"d"A $
是横截面的部分面积 $A_1$ 对中性轴的静矩。

一般说，在剪力为最大值的截面的中性轴上，出现最大切应力，且
$ tau _"max" = frac(F_"Smax"S^*_"zmax", I_z b) $

*矩形*截面梁的最大切应力
$ tau _"max" = frac(3, 2)frac(F_"S", bh) $
为平均切应力的 1.5 倍。

*圆形*截面梁的最大切应力
$ tau _"max" = frac(4, 3)frac(F_"S", pi R^2) $
为平均切应力的 $frac(4, 3)$ 倍。

=== 提高弯曲强度的措施

对抗拉和抗压强度相同的材料（如碳钢）宜采用中性轴对称的截面，对抗拉和抗压强度不相等的材料（如铸铁）宜采用中性轴*偏向于受拉一侧*的截面形状。
如能使 $y_1$ 和 $y_2$ 之比接近于下列关系：
$ frac( sigma _"tmax", sigma _"cmax") = frac(M_"max"y_1, Iz)/frac(M_"max"y_2, Iz) = frac(y_1, y_2) = frac([ sigma _"t"], [ sigma _"c"]) $
式中 $[ sigma _"t"]$ 和 $[ sigma _"c"]$ 分别表示拉伸（Tension）和压缩（Compression）的许用应力，则最大拉应力和最大压应力可同时接近许用应力。
强度校核时超过百分之 $5$ 以内都可接受（跟开车超速一点点不扣分差不多）。

== 弯曲变形

=== 挠曲线的微分方程

发生弯曲变形时，变形前为直线的梁轴线，变形后成为一条连续且光滑的曲线，称为*挠曲线*。

=== 用积分法求弯曲变形

边界条件：在固定端，挠度和转角都为零，在铰支座上，挠度为零。
$ EIw'' = M(x) $
然后对 $x$ 积分两次，代入边界条件和连续条件确定积分常数，得到挠曲线方程。
注意 $w'$ 即为 $theta$ 。

=== 用叠加法求弯曲变形

*弯曲变形很小*且材料服从*胡克定律*时，挠曲线的微分方程是线性的。

== 应力和应变分析 强度理论

=== 应力状态概述

切应力等于零的面称为*主平面*，主平面上的正应力称为主应力。

=== 二向和三向应力状态的实例

圆筒的壁厚 $delta$ 远小于它的内径 $D$ 时，称为*薄壁圆筒*。若封闭的薄壁圆筒所受内压为 $p$ ，则其横截面上应力
$ sigma ' = frac(F, A) = frac(p dot.op "frac" pi D^2, 4) pi D delta = frac(pD, 4 delta ) $
纵向截面上应力
$ sigma '' = frac(pD, 2 delta ) $

在研究一点的应力状态时，通常用 $sigma _1, sigma _2, sigma _3$ 代表该点的三个主应力，并以 $sigma _1$ 代表代数值最大的主应力，$sigma _3$ 代表代数值最小的主应力，即 $sigma _1 "geqslant" sigma _2 "geqslant" sigma _3$ 。

=== 二向应力状态分析————解析法

$sigma _x$ 和 $tau _(xy)$ 是*法线与 $x$ 轴平行*的面上的正应力和切应力；$sigma _y$ 和 $tau _(yx)$ 是*法线与 $y$ 轴平行*的面上的正应力和切应力。
符号规定：正应力拉正压负，切应力对单元体内任意点的矩为*顺时针*转向时为正，反之为负，这里与平常不同。
取任意斜截面，其外法线 $n$ 与 $x$ 轴的夹角为 $alpha$ 。规定：由 $x$ 轴转到*外法线* $n$ 为*逆时针*转向时，则 $alpha$ 为正。

$ .
"beginaligned"
 sigma _"max" \\
 sigma _"min"
"endaligned"
\}
= frac( sigma _x+ sigma _y, 2) plus.minus sqrt((frac( sigma _x- sigma _y, 2))^2 + tau _(xy)^2) $
$ .
"beginaligned"
 tau _"max" \\
 tau _"min"
"endaligned"
\}
= plus.minus sqrt((frac( sigma _x- sigma _y, 2))^2 + tau _(xy)^2) $
$ sigma _ alpha = frac( sigma _x+ sigma _y, 2) + frac( sigma _x- sigma _y, 2) cos 2 alpha - tau _(xy) sin 2 alpha \\
 tau _ alpha = frac( sigma _x- sigma _y, 2) sin 2 alpha + tau _(xy) cos 2 alpha $

=== 二向应力状态分析————图解法

上面两式两边平方然后相加可消去 $alpha$ ，得
$ ( sigma _ alpha -frac( sigma _x+ sigma _y, 2))^2 + tau _ alpha ^2 = (frac( sigma _x- sigma _y, 2))^2 + tau _(xy)^2 $
$sigma _x, sigma _y, tau _(xy)$ 均为已知量，可此式是一个以 $sigma _ alpha$ 和 $tau _ alpha$ 为变量的圆方程，以横坐标表示 $sigma$ ，纵坐标表示 $tau$ ，则圆心横坐标为 $frac(1, 2)( sigma _x+ sigma _y)$ ，纵坐标为零，半径为 $sqrt((frac( sigma _x- sigma _y, 2))^2 + tau _(xy)^2)$ 。这一圆周称为*应力圆*。

作法：

+ 在坐标系取点 $A( sigma _x,0)$ ，$D( sigma _x, tau _(xy))$ ，$B( sigma _y,0)$ ，$D'( sigma _y,- tau _(xy))$ 。
+ 连接 $D$ 和 $D'$ ，与横坐标交于 $C$ 点，以 $C$ 为圆心， $CD$ 为半径画圆，得到应力圆。

在应力圆上，从 $D$ 点（它代表以 $x$ 轴为法线的面上的应力）也按逆时针方向沿圆周转到 $E$ 点，且使 $DE$ 弧所对圆心角为 $alpha$ 的 $2$ 倍，则 $E$ 点的坐标就代表以 $n$ 为法线的斜面上的应力。

=== 三向应力状态

$ sigma _"max" = sigma _1, quad sigma _"min" = sigma _3, quad tau _"max" = frac( sigma _1- sigma _3, 2) $
$sigma _2$ 就是一般就是垂直于 $sigma _1$ 和 $sigma _3$ 的应力。

=== 广义胡克定律

$ epsilon.alt _x = frac(1, E)[ sigma _x- mu ( sigma _y+ sigma _z)] $

$ epsilon.alt _1 = frac(1, E)[ sigma _1- mu ( sigma _2+ sigma _3)] \\
 epsilon.alt _2 = frac(1, E)[ sigma _2- mu ( sigma _1+ sigma _3)] \\
 epsilon.alt _3 = frac(1, E)[ sigma _3- mu ( sigma _1+ sigma _2)] $

=== 四种常用强度理论

最大拉应力理论（第一强度理论）
$ sigma _("r"1) = sigma _1 $
最大伸长线应力理论（第二强度理论）
$ sigma _("r"2) = sigma _1 - mu ( sigma _2+ sigma _3) $
最大切应力理论（第三强度理论）
$ sigma _("r"3) = sigma _1 - sigma _3 $
最大畸变能密度理论（第四强度理论）
$ sigma _("r"4) = sqrt(frac(1, 2)[( sigma _1- sigma _2)^2+( sigma _2- sigma _3)^2+( sigma _3- sigma _1)^2]) $

=== 莫尔强度理论

$ sigma _"rM" = sigma _1 - frac([ sigma _t], [ sigma _c]) sigma _3 $

== 组合变形

=== 扭转与弯曲的组合

$ M = sqrt(M_(y"max")^2+M_z"max")^2 $
按第三强度理论，有
$ sqrt( sigma ^2+4 tau ^2) "leqslant" [ sigma ] \\
frac(1, W)sqrt(M^2+T^2) "leqslant" [ sigma ] $
按第四强度理论，有
$ sqrt( sigma ^2+3 tau ^2) "leqslant" [ sigma ] \\
frac(1, W)sqrt(M^2+0.75T^2) "leqslant" [ sigma ] $

== 压杆稳定

=== 压杆稳定的概念

细长杆件受压时，设压力与轴线重合，压力小于某一极限值时，压杆一直保持*直线*形状的平衡，即便有微小的侧向干扰力使其暂时发生轻微弯曲，干扰力解除后，压杆也能恢复直线形状，这表明压杆直线形状的平衡是稳定的。但是如果压力大于某一极限值时，压杆的直线平衡变为不稳定，将转变为*曲线*形状的平衡。这时再用微小的侧向干扰力使其发生轻微弯曲，干扰力解除后，它将保持曲线形状的平衡，不能恢复到原有的直线形状。

上述压力的极限值称为临界压力或临界力，记为 $F_"cr"$ 。压杆丧失其直线形状的平衡而过渡为曲线平衡，称为丧失稳定性，简称*失稳*，也称为屈曲。

=== 其他支座条件下细长压杆的临界压力

欧拉公式的普遍形式为
$ F_"cr" = frac( pi ^2EI, ( mu l)^2) $
式中 $mu l$ 表示把压杆折算成两端铰支杆的长度，称为相当长度，$mu$ 称为长度因数，不同情况下的长度因数 $mu$ 列表如下：

| 压杆的约束条件 | 长度因数 |
| :-- | :-- |
| 两端铰支 | $mu =1$ |
| 一端固定，另一端自由 | $mu =2$ |
| 两端固定 | $mu =frac(1, 2)$ |
| 一端固定，另一端铰支 | $mu approx 0.7$ |

=== 欧拉公式的适用范围 经验公式

$ sigma _"cr" = frac(F_"cr", A) = frac( pi ^2EI, ( mu l)^2A) $
$sigma _"cr"$ 称为临界应力。把横截面的惯性矩 $I$ 写成
$ I = i^2A $
上式可以写成
$ sigma _"cr" = frac( pi ^2E, ("frac" mu l){i)^2A} $
引用记号
$ lambda = frac( mu l, i) $
$lambda$ 是一个量纲一的量，称为柔度或长细比，综合反映了压杆的长度、约束条件、截面尺寸和形状等因素对临界应力 $sigma _"cr"$ 的影响。计算临界应力的公式可以写成
$ sigma _"cr" = frac( pi ^2E, lambda ^2) $
这是欧拉公式的另一种表达形式，其适用范围为
$ lambda "leqslant" lambda _"p" = "pisqrt"(frac(E, sigma _"p")) $

=== 压杆的稳定性校核

$F_"cr"$ 与 $F$ 之比即为压杆的工作安全因数 $n$，它应大于规定的稳定安全因数 $n_"st"$，即
$ n = frac(F_"cr", F) "geqslant" n_"st" $

== 平面图形的几何性质

=== 静矩和形心

在坐标 $(y,z)$ 处，取微面积 $"d"A$ ，遍及整个图形面积 $A$ 的积分
$ S_z = integral _A y"d"A, quad S_y = integral _A z"d"A $
分别定义为图形对 $z$ 轴和 $y$ 轴的*静矩*，也称为图形对 $z$ 轴和 $y$ 轴的*一次矩*。
这个坐标轴之所以只有 $y$ 和 $z$ 而没有 $x$ ，是因为我们一般分析的是横截面，$x$ 轴是杆的轴线方向。
可以看出，平面图形的静矩是对某一坐标轴而言的，也就是说，同一图形对不同的坐标轴的静矩通常是不同的。静矩的量纲是长度的三次方。

平面图形对 $y$ 轴和 $z$ 轴的静矩，分别等于*图形面积* $A$ *乘形心的坐标* $overline(z)$ 和 $overline(y)$ ，即
$ S_z = A"cdotoverline"(y), quad S_y = A"cdotoverline"(z) $

=== 惯性矩和惯性半径

在坐标 $(y,z)$ 处，取微面积 $"d"A$ ，遍及整个图形面积 $A$ 的积分
$ I_y = integral _A z^2"d"A, quad I_z = integral _A y^2"d"A $
分别定义为图形对 $y$ 轴和 $z$ 轴的*惯性矩*，也称为图形对 $y$ 轴和 $z$ 轴的*二次矩*。惯性矩的量纲是长度的四次方。
矩形的对形心轴的 $I_z$ 为 $frac(bh^3, 12)$ 。
力学计算中，有时把惯性矩写成图形面积 $A$ 与某一长度的平方的乘积，即
$ I_y = A dot.op i_y^2, quad I_z = A dot.op i_z^2 $
或者改写为
$ i_y = sqrt(frac(I_y, A)), quad i_z = sqrt(frac(I_z, A)) $
式中的 $i_y$ 和 $i_z$ 分别称为图形对 $y$ 轴和 $z$ 轴的*惯性半径*。惯性半径的量纲就是长度的量纲。

以 $rho$ 表示微面积 $"d"A$ 到坐标原点 $O$ 的距离，下列积分
$ I_"p" = integral _A rho ^2"d"A $
定义为图形对坐标原点 $O$ 的*极惯性矩*。又 $rho ^2 = y^2+z^2$ ，于是有
$ I_"p" = integral _A (y^2+z^2)"d"A = integral _A y^2"d"A + integral _A z^2"d"A = I_z + I_y $

=== 惯性积

在坐标 $(y,z)$ 处，取微面积 $"d"A$ ，遍及整个图形面积 $A$ 的积分
$ I_(yz) = integral _A yz"d"A $
定义为图形对 $y,z$ 轴的*惯性积*。惯性积的量纲是长度的四次方。
坐标系的两根坐标轴中只要有一根为图形对称轴，则图形对这一坐标系的惯性积就等于零。

=== 平行移轴公式

$ I_y = I_(yC) + a^2A \\
I_z = I_(zC) + b^2A \\ $
