#import "../../config.typ": *

#show: template-post.with(
  title: "DeepSeek-V4 技术报告分析学习",
  description: "感恩 DeepSeek，愿开源精神永存",
  tags: ("LLM", "AI",),
  category: "AI",
  date: datetime(year: 2026, month: 4, day: 18, hour: 19, minute: 19, second: 0)
)

== 前言

首先制造点焦虑，不然容易缺乏学习动机。

笔者认为（或者说臆测），在现在的时代，LLM 相关的知识已经相当于高考——可能生活甚至实际工作中很多是用不上的，但是从用人单位的角度来衡量，在专业领域知识差异被 LLM 缩小的情况下，你要是能对 LLM 本身有比较深入的了解，那么这无疑是一个非常具备竞争力的优势。

原文指路：#link("https://huggingface.co/deepseek-ai/DeepSeek-V4-Pro/blob/main/DeepSeek_V4.pdf")

这篇文章仅仅是对原文的简单概述和思考，笔者还是希望有时间的读者阅读一下原文。
对于每一个笔者不熟悉，或者笔者认为小白读者可能不熟悉的概念，笔者都有标记，读者可以点击以跳转其在文末的概念解释部分。
同时与科普文不同，本文会大量引入公式，直接解释底层的数学原理，拒绝强行不恰当比喻造成的理解偏差。
#success(title: "Promise")[文章保证 aigc 率不高于 10%，秉承匠心精神，坚持古法手打。]

下面我们正式从一个比较小白的视角去分析写文章这个时间节点最前沿的技术文章。

== 技术报告

=== 摘要

我们提出了预览版的 DeepSeek-V4 系列，包括两个 #link(<moe>)[MoE] 语言模型 —— 1.6T 参数量（49B 激活）的 DeepSeek-V4-Pro 和 284B 参数量（13B 激活）的 DeepSeek-V4-Flash，均支持 1M tokens 的 #link(<context>)[context]。
三个比较关键的更新：

+ 用 CSA 和 HCA 来增强长 context 下的效率
+ 用 #link(<mhc>)[mHC] 增强传统的残差连接
+ 用 Muon optimizer 来做到更快的收敛和更稳定的训练

我们先用超过 32T 多样且高质量的 tokens 来对以上两个模型做预训练，然后做了一个全面的后训练流程以解锁和进一步增强它们的能力。
吧啦吧啦，总之 DeepSeek-V4-Pro 很牛逼。
在百万 context 时，DeepSeek-V4-Pro 的单 token 推理 #link(<flops>)[FLOPs] 仅为 DeepSeek-V3.2 的 27%，而其 #link(<kv-cache>)[KV cache] 需求仅为 10%。

== 相关概念

=== context <context>

即模型上下文，通常以 #link(<token>)[token] 为单位，可以近似理解为 LLM 能接收的最长有效输入。

=== token <token>

LLM 的输入和输出都是以 token 为单位的，中文翻译的*词元*其实是比较直观的。

对英文来说，token 可以是一个单词，也可以是一个 subword（例如“unhappy”这个单词可能被分成“un”和“happy”两个 token），甚至可以是一个字符（例如“a”）。对于中文来说，token 通常是一个汉字，但也有可能是一个词语（例如“人工智能”可能被分成“人工”和“智能”两个 token）。

总之大概来说，分词器（Tokenizer）会尽量把文本切成又大又小的 token —— 大到能表达一个完整的语义，小到只能表达的语义一般只有一个。

=== MoE <moe>

即 Mixture-of-Experts，大概就是在模型里面植入一个*路由机制*，检测到哪些领域比较相关就分配给哪些专家。
MoE 架构有一个特点，作为一个稀疏模型（Sparse Model），它每次 input 的 tokens 都会过一个路由（Router），只激活 Top-K（V4 选取了 6）个相关领域的专家来处理，其他领域的专家相关参数则不会被激活，这样既保证了模型有极广的知识储备，又可以因为激活的参数量少而大大减少计算成本。
与稀疏模型相反的稠密模型（Dense Model）则是每次都会使用全参数计算。

=== KV Cache <kv-cache>

全称 Key-Value Cache，是 LLM 在推理阶段的关键加速技术。
对这个感到迷惑的读者，一般对*注意力机制（Self-Attention）* 也不会有太深入的了解，下面会一并提及。
在 Transformer 的注意力机制中，输入的每个 token 都会转换成三个*向量*：

+ #text(fill: green)[Q (Query / 查询)]：当前词正在*寻找*什么信息？
+ #text(fill: green)[K (Key / 键)]：每个词拥有什么*特征*？
+ #text(fill: green)[V (Value / 值)]：每个词包含的*具体内容*是什么？

你可能会觉得这有点模糊，但是现在 LLM 就是逐渐朝着不可解释发展，现在这东西还能有个含义，已经是很不错了。
有点扯远了，其实这涉及理解东西的一个关键技巧，就是不要太局限化思维，死磕这个矩阵为什么表示这个含义是没有用的，现在只需要有这个概念，慢慢地脑子就会建立起整个条件反射，或者说是整个宏观叙事。
扯得更远了（

#quote[
注意力的计算公式只有一行：

$
op("Attention")(Q, K, V) = op("softmax")(frac(Q dot K^T, sqrt(d_k))) V
$
]

首先不要跟我一样，一看到公式就脑子自动屏蔽并跳过该内容，下面来解释一下这个公式，其实非常简单易懂。

+ *计算相似度。*$Q K^T$ 就是让 $Q$ 矩阵（对单个 token 来说是向量，这里可以先视作一维矩阵）和 $K$ 矩阵相乘 #strike[（不会还有人不知道维度相同的矩阵相乘要转置的吧）]，两个向量的相似度越高，点积就越大，表示匹配程度越高。注意这里的 $Q$ 和 $K$ 在 Transformer 里并没有归一化，其欧几里得范数（即模长，也叫 L2 范数）*不是相等的*。

+ *归一化权重。*$d_k$ 为 $K$ 向量的维度，因为向量点积的结果是随维度增大而增大的，这样会导致一个问题：#link(<softmax>)[softmax 函数]作为一个用指数来归一化的函数，会把差异放得非常大，这样会导致 —— 其中某个值特别大的时候，其概率分布会趋近于 1，其他的概率分布都会趋近于 0，进而导致在反向传播计算时，梯度会趋近于 0，即陷入*梯度消失（Vanishing Gradient）*。所以在喂进 softmax 函数前，我们要先做一个*缩放（Scale）*，让数值落在 Softmax 梯度丰富的敏感区域。

  #quote[
  那为什么缩放因子选择的是 $1/sqrt(d_k)$？
  + 我们假设 $Q$ 和 $K$ 里的每个元素 $q_i$ 和 $k_i$ 都是独立同分布的随机变量在模型初始化时满足 —— *均值为 0 且方差为 1*
  + 点积计算，即
   $
   Q dot K = sum_(i=1)^(d_k) q_i k_i
   $
    对任意一对 $q_i k_i$，根据概率论，均值为 0 时，两个独立变量乘积的方差等于它们各自方差的乘积，所以 $q_i k_i$ 的方差仍然是 1 \
    但是点积把 $d_k$ 个这样的乘积*加*到了一起。又根据统计学原理，独立变量相加，总方差等于各变量方差之和 \
    所以这时点积的总方差就是 $d_k$
  + 又双叒叕根据统计学定理：如果一个随机变量 $X$ 的方差是 $V a r(X)$，那么把它除以一个常数 $c$ 之后，新的方差会变成 $(V a r(X)) / c^2$。 \
    我们希望新方差为 1 时，有如下方程：
   $
   d_k / c^2 = 1
   $
    相信对于读者也不难解出 $c = sqrt(d_k)$\
    证毕。
  ]

+ *加权求和。* 用归一化后的概率分布乘上所有的 $V$，即含义矩阵，结果就是概率越高的 $V$ 对最终结果的影响越大，或者更为严谨地说是其越容易影响最终的结果（因为不排除有些 $V$ 本身就很大，就算概率小也不容易被压下去）

=== Softmax 函数 <softmax>

$
op("softmax")(x_i) = frac(e^(x_i), sum_j e^(x_j))
$

=== 方差和标准差

这就属于温习了。
方差公式：

$
sigma^2 = frac(sum (x_i - mu)^2, N)
$

标准差就是方差开个方，即其算术平方根。

=== FLOPs <flops>

全称 Floating-Point Operations，也就是浮点运算的次数，在 LLM 推理中可以直接近似理解成*计算量*。
和这个有点像的是 FLOPS，但是是大写的 S，全称 Floating-Point Operations *Per Second*，表示每秒能执行的浮点运算次数，是衡量*硬件性能（如 GPU/TPU）* 的重要标准。
至于为什么是浮点运算，我也不是很能解释得清楚，至少在行业实践中，浮点运算已经和 AI 领域深度绑定了。

=== CSA

=== HCA

=== mHC <mhc>

其实这个东西是 DeepSeek 在元旦发的论文《mHC: Manifold-Constrained Hyper-Connections》（原文链接：#link("https://arxiv.org/pdf/2512.24880")）里提出来的，文章内容不多，去掉参考文献也才 15 页，感兴趣的读者也可以看看原文。
全称就是论文的题目，中文翻译过来叫*流形约束超连接*。

先从传统残差连接讲起。

==== 传统残差连接

#error(title: "Problem")[
  众所周知，深度学习两大问题：一是*梯度消失*，二是*梯度爆炸*。

  理论上来说，层数越多，模型提取特征的能力越强，效果越好。
  但是，在网络套到一定层数的时候，不仅训练变得困难，深层网络的准确率居然反而还不如浅层网络 —— 这个在学术上称为*网络退化问题（Degradation Problem）*

  原因也比较朴素：传统的深层网络太难优化 —— 信息流过多层后丢失严重，误差的反向传播同样如此。差不多意思就是，前面的数字从负无穷变到正无穷了，传到后面的变化可能已经到小数点后几位去了。

  这就是*梯度消失*害的。
]

这时候*残差连接（Residual Connection）* 就来了，每一层的输出不直接喂给下一层，而是补上一手原始输入再喂，公式如下：

$
x_(l+1) = x_l + F(x_l)
$

其中 $x_l$ 和 $x_(l+1)$ 分别表示第 $l$ 层的输入和输出。
将这个公式倒一倒：

$
F(x_l) = x_(l+1) - x_l
$

我们神奇地发现，这一层的变换函数直接就是输出与输入的差值，换个意思就是 —— 这一层现在学习的是变化量，而我们称这个变化量为*残差*。

为什么说传统残差是*累加的*？

这个概念会在后面提到，也是相关科普视频反复会提及的一点。
$
x_(l+1) &= x_l + F(x_l) \
x_(l+2) &= x_(l+1) + F(x_(l+1))
$

代入得：

$
x_(l+2) = x_l + F(x_l) + F(x_(l+1))
$

继续套到第$L$层：

$
x_L = x_0 + sum_(i=0)^(L-1) F(x_i)
$

直观上理解，$x_L$，即第 $L$ 层的输出，也就是第 $L$ 层的特征，就是最原始的输入 $x_0$，*累加*上中间所有层提取出的残差。

求导有：

$
frac(partial x_L, partial x_l) = 1 + frac(partial, partial x_l) sum_(i=l)^(L-1) F(x_i)
$

这个“1”就是残差网络保证梯度不消失的关键，即便后面那坨趋于 0，总梯度也有这个“1”兜底。

可能这时你会想，要是后面那坨是 -1 怎么办？
实际上，真实网络都是高维的，上面那版公式只是为了方便理解一点，完全体的求导公式应该长这样：

$
frac(partial x_L, partial x_l) = I + frac(partial, partial x_l) sum_(i=l)^(L-1) F(x_i)
$

要想让后面那坨（此时它有个正式点的名字，叫雅可比矩阵）捏成 $-I$，只能说挺难的。

==== HC

#error(title: "Problem")[
  然而残差连接仅仅是解决了*梯度消失*的问题，其仍然存在局限性：

  + *连接太死板*：$x_l$ 和 $F(x_l)$ 相加的权重固定
  + Representation Collapse，即*表征坍塌*，就是后面的深层网络开混，提取出来跟前面差不多的玩意，没有实际有用输出
]

那既然都提到这两点了，下面的即将出场的就是由字节跳动的 Seed 团队提出的 HC，即 Hyper-Connections 搞定的就是它们了。

对应论文链接为 #link("https://arxiv.org/pdf/2409.19606")，文章页数也不多。

HC 的核心公式为：

$
bold(X)_(l+1) = bold(H)_l^"res" bold(X)_l + (bold(H)_l^"post")^top cal(F)(bold(H)_l^"pre" bold(X)_l)
$

#warning(title: "注：")[公式格式不太统一是因为我会尽量采用对应论文的格式]

HC 将单一的特征流扩展到 $n$ 条，输入也从向量变成了矩阵 $bold(X)_l in RR^(n times C)$。

可以看到公式里出现了三个矩阵：

- $bold(H)_l^"pre"$(Pre Mapping)：负责“读”。将 $n$ 条流的信息聚合，送入当前层 $cal(F)$ 进行计算。
- $bold(H)_l^"post"$(Post Mapping)：负责“写”。将当前层算出的结果，重新分配回 $n$ 条流中。
- $bold(H)_l^"res"$(Res Mapping)：这是核心的混合矩阵。它直接对 $n$ 条残差流进行加权混合（例如决定第 1 条流分给第 2 条流多少信息）。

#import "@preview/fletcher:0.5.8" as fletcher: diagram, node, edge
#{
  let hc-diagram = diagram(
    node-stroke: 1pt,
    edge-stroke: 1pt,
    node-inset: 12pt,
    node((0,0), [$bold(X)_l$], stroke: none),
    
    // Residual path (top)
    node((1,-0.5), [$bold(H)_l^"res"$], shape: "rect"),
    
    // Main path (bottom)
    node((1,0.5), [$bold(H)_l^"pre"$], shape: "rect"),
    node((2,0.5), [$cal(F)$], shape: "rect"),
    node((3,0.5), [$(bold(H)_l^"post")^top$], shape: "rect"),

    // Addition node
    node((4,0), [$+$], shape: "circle"),
    
    // Output node
    node((5,0), [$bold(X)_(l+1)$], stroke: none),

    edge((0,0), (1,-0.5), "-|>", corner: left),
    edge((1,-0.5), (4,0), "-|>", corner: right),
    
    edge((0,0), (1,0.5), "-|>", corner: right),
    edge((1,0.5), (2,0.5), "-|>"),
    edge((2,0.5), (3,0.5), "-|>"),
    edge((3,0.5), (4,0), "-|>", corner: left),
    
    edge((4,0), (5,0), "-|>"),
  )

  figure(
    caption: [HC 核心公式中三个矩阵的作用],
    auto-frame(hc-diagram)
  )
}

$
x_(l+1) = cal(H)_l^"res" x_l + cal(H)_l^("post"top) cal(F)(cal(H)_l^"pre" x_l, cal(W)_l)
$

$
cal(x)_(l+1) = x_l + cal(F)(x_l, cal(W)_l)
$

其中 $cal(x)_l$ 和 $cal(x)_(l+1)$ 分别表示第 $l$ 层的输入和输出。

$
x_(l+1) = cal(H)_l^"res" x_l + cal(H)_l^("post"top) cal(F)(cal(H)_l^"pre" x_l, cal(W)_l)
cal(P)_(cal(M)^"res")(cal(H)_l^"res") := { cal(H)_l^"res" in RR^(n times n) mid(|) cal(H)_l^"res" bold(1)_n = bold(1)_n, bold(1)_n^top cal(H)_l^"res" = bold(1)_n^top, cal(H)_l^"res" >= 0 }
$

=== Muon optimizer

== 参考

#link("https://mp.weixin.qq.com/s/IED0AJ7p6LJoETNP7PlVAQ") \
#link("https://mp.weixin.qq.com/s/-oVGdaNcQXKuN2nQQ6BkzA")