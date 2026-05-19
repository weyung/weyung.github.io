#import "../../../config.typ": *

#show: template-post.with(
  title: "高数上笔记",
  description: "忽然能转了，尝试速成高数上",
  tags: ("数学", "高数",),
  category: "Course",
  date: datetime(year: 2023, month: 5, day: 5)
)

== 前言

有空再写。

== 笔记正文

=== 第一章 函数与极限

==== 连续函数

===== 间断点的分类

=== 第二章 微积分的基本概念

==== 不定积分

===== 积分表

+ $integral x^alpha "d"x = frac(1, alpha +1)x^(alpha +1)+C(alpha != -1)$
+ $integral cos x"d"x = sin x+C$;$integral sin x"d"x = -cos x+C$
+ $integral sec ^2x"d"x = tan x+C$;$integral csc ^2x"d"x = -cot x+C$
+ $intfrac("d"x, 1+x^2) = arctan x+C$;$intfrac("d"x, sqrt(1-x^2)) = arcsin x+C$
+ $intalpha ^x"d"x = frac(1, lnalpha )alpha ^x+C(alpha >0,alpha != 1)$
+ $integral frac1x"d"x = ln |x|+C$

=== 第三章 积分的计算及应用

=== 第四章 微分中值定理与泰勒公式

微分中值定理又称为*拉格朗日中值定理*：设 $y=f(x)$ 在 $[a,b]$ 上连续，在 $(a,b)$ 内可导，则必存在一点 $cin (a,b)$，使得
$ f'(c) = frac(f(b)-f(a), b-a) $

*例* 证明当 $e < a < b < e^2$ 时，$(b-a)frac(2, e^2)<ln ^2b-ln ^2a<frac4e(b-a)$
*解*

==== 泰勒公式

常用 $\ (xarrow0)$：

+ $e^x=1+x+frac(1, 2!)x^2+dots.c +frac(1, n!)x^n+o(x^n)$
+ $sin x = x - frac(1, 3!)x^3 + dots.c + (-1)^(n-1)fracx^(2n-1)(2n-1)! + o(x^(2n))$
+ $cos x = 1 - frac(1, 2!)x^2 + dots.c + (-1)^nfracx^(2n)(2n)! + o(x^(2n+1))$
+ $ln (1+x) = x - frac(x^2, 2) + frac(x^3, 3) + dots.c + (-1)^(n-1)frac(x^n, n) + o(x^n)$
+ $(1+x)^alpha = 1 + alpha x + frac(alpha (alpha -1), 2!)x^2 + dots.c + frac(alpha (alpha -1)dots.c (alpha -n+1), n!)x^n + o(x^n)$

=== 第五章 向量代数与空间解析几何
