#import "../../../config.typ": *
#import "@preview/tablem:0.3.0": *
#import "@preview/citegeist:0.2.0": load-bibliography
#import "@preview/cmarker:0.1.8"
#import "@preview/mitex:0.2.6": *

#show: template-post.with(
  title: "Typst 功能展示",
  description: "本文主要展示了一些常用的 Typst 语法，并给出一些增强功能。",
  tags: ("Typst", "写作指南"),
  category: "如何编写博客文章",
  date: datetime(year: 2026, month: 3, day: 18)
)

= 基础功能

Typst 内置了基础的文字修饰功能，对应的代码和效果如下表所示。

#table(
  columns: 2,
  table.header(
    [代码], [效果],
  ),
  [```typ *粗体*```], [*粗体*],
  [```typ _斜体_```], [_斜体_],
  [```typ #underline[下划线]```], [#underline[下划线]],
  [```typ #strike[删除线]```], [#strike[删除线]],
  [```typ #overline[上划线]```], [#overline[上划线]],
  [```typ #super[上标]文本#sub[下标]```], [#super[上标]文本#sub[下标]],
  [```typ #highlight[高亮标记]```], [#highlight[高亮标记]],
)

你可以通过粘贴 URL 或者 ```typ #link``` 函数创建一个链接：

#table(
  columns: 2,
  table.header(
    [代码], [效果],
  ),
  [```typ https://typst.app/```], [https://typst.app/],
  [```typ #link("/about/")[关于页面]```], [#link("/about/")[关于页面]],
)

你可以使用 `#divider()` 创建分割线，效果如下：

#divider()

你可以通过如下代码创建一些列表：

```typ
- 文字
- 数学公式
- 代码块
  - 内联代码块
  - 块级代码块
  
+ 这是有序列表的第 1 项。
3. 可以使用任意数字创建一个新的有序列表，此时
+ 序号会从上次出现的有序列表项继续递增，这里就是 4。
1. 这里的序号又回到了 1，但它依然会继续递增，所以
+ 这里的序号是 2。

/ 连字: 合并的字形。
/ 字距调整: 两个相邻字母之间的间距调整。
```

渲染效果如下：

- 文字
- 数学公式
- 代码块
  - 内联代码块
  - 块级代码块
  
+ 这是有序列表的第 1 项。
3. 可以使用任意数字创建一个新的有序列表，此时
+ 序号会从上次出现的有序列表项继续递增，这里就是 4。
1. 这里的序号又回到了 1，但它依然会继续递增，所以
+ 这里的序号是 2。

/ 连字: 合并的字形。
/ 字距调整: 两个相邻字母之间的间距调整。

= 常用内容块

除了基础的文字修饰功能，Carbon Typst Blog 提供了一些常用的内容块，例如引用块、注意块、表格和代码块等。你也可以通过 `#quote` 函数创建一个引用块，或者通过 `#note`、`#success`、`#warning` 和 `#error` 创建一些带有标题的强调块。

```typ
#quote[
  这是一个引用块。
  #quote[这是引用块中的引用块。]
]
#note(title: "提示")[这是一个注意块。]
#success(title: "完成")[这是一个强调块。]
#warning(title: "警告")[这是一个警告块。]
#error(title: "注意")[
  这是一个带多段内容的块。

  这一行用于展示换行效果。
]
```

对应的渲染效果如下：

#quote[
  这是一个引用块。
  #quote[这是引用块中的引用块。]
]
#note(title: "提示")[这是一个注意块。]
#success(title: "完成")[这是一个强调块。]
#warning(title: "警告")[这是一个警告块。]
#error(title: "注意")[
  这是一个带多段内容的块。

  这一行用于展示换行效果。
]

= 表格、代码块与图表

Typst 内置了表格和代码块的支持，你可以通过 `#table` 和 #raw(lang: "typst", block: false, "```[lang] ```") （对于内联代码块，则使用 #raw(lang: "typst", block: false, "` `") 或 #raw(lang: "typst", block: false, "```[lang] ```")）来创建它们。另外，你可以通过 `#figure` 函数创建一个带有标题的内容块，并将表格、代码块或者图像等内容放在其中，从而让它们拥有一个标题。以下是一些示例：

#raw(lang: "typst", block: true,
"#figure(caption: [示例表格])[
  #table(
    columns: (1fr, 2fr, auto),
    table.header([姓名], [简介], [状态]),
    [Alice], [前端开发者，喜欢 Rust], [在线],
    [Bob], [后端工程师，喜欢 Python], [离线],
  )
]<tbl1>

#figure(caption: \"代码块样式示例\")[
  ```rs
  fn main() {
    println!(\"Hello, Typst!\");
  }
  ```
]<code1>")

对应的渲染效果如下：

#figure(caption: [示例表格])[
  #table(
    columns: (1fr, 2fr, auto),
    table.header([姓名], [简介], [状态]),
    [Alice], [前端开发者，喜欢 Rust], [在线],
    [Bob], [后端工程师，喜欢 Python], [离线],
  )
]<tbl1>

#figure(caption: "代码块样式示例")[
  ```rs
  fn main() {
    println!("Hello, Typst!");
  }
  ```
]<code1>

需要注意，由于 Typst 的 HTML 导出问题，页面上表格的宽度和对齐方式暂时无法调整。

你也可以使用外部的图像库绘制图像，并通过 SVG 格式将它们嵌入到页面中（*需要将图像变量包裹在 `auto-frame` 函数中*）。默认情况下，SVG 在深色模式下会被反转颜色，如果你不希望它被反转，可以将 `auto-frame` 函数的 `disable-filter` 参数设置为 `true`。以下是一个使用 `lilaq` 库绘制二维函数图像的示例：

```typ
#import "@preview/lilaq:0.5.0" as lq
#{
  let diagram = lq.diagram(
    width: 4cm, height: 4cm,
    lq.colormesh(
      lq.linspace(-4, 4, num: 10),
      lq.linspace(-4, 4, num: 10),
      (x, y) => x * y,
      map: color.map.magma
    )
  )

  figure(caption: [二维函数 $f(x, y) = x y$], auto-frame(disable-filter: true, diagram))
}
```

上述代码绘制了一个简单的二维函数图像，并通过 `figure` 函数创建了一个带有标题的内容块来展示它。对应的渲染效果如下：

#import "@preview/lilaq:0.5.0" as lq
#{
  let diagram = lq.diagram(
    width: 4cm, height: 4cm,
    lq.colormesh(
      lq.linspace(-4, 4, num: 10),
      lq.linspace(-4, 4, num: 10),
      (x, y) => x * y,
      map: color.map.magma
    )
  )

  figure(caption: [二维函数 $f(x, y) = x y$], auto-frame(disable-filter: true, diagram))
}


= 数学、引用与交叉引用

行内公式示例：$f(x) = x^2$。

块级公式示例：
$
  f(x) & = (x + 1)^2 \
       & = x^2 + 2x + 1
$

较长的公式可以通过横向滚动查看：

// 一元三次方程的根
// 使用 Typst 风格给出

#let over(a, b) = a / b

$
x = frac(
  -3b plus.minus ( 
    sqrt(3 ( 3b^2 - 8a c + 2a root(3, 4 ( 2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e + sqrt((2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e)^2 - 4(c^2 - 3b d + 12a e)^3) )) + 2a root(3, 4 ( 2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e - sqrt((2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e)^2 - 4(c^2 - 3b d + 12a e)^3) )) )) 
    plus.minus 
    sqrt(3 ( 3b^2 - 8a c + 2a ((-1+sqrt(-3))/2) root(3, 4 ( 2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e + sqrt((2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e)^2 - 4(c^2 - 3b d + 12a e)^3) )) + 2a ((-1-sqrt(-3))/2) root(3, 4 ( 2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e - sqrt((2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e)^2 - 4(c^2 - 3b d + 12a e)^3) )) )) 
  ) 
  plus.minus 
  "sgn" ( 
    ( "sgn"(-b^3 + 4a b c - 8a^2 d) - 1/2 ) 
    ( "sgn"( max( (2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e)^2 - 4(c^2 - 3b d + 12a e)^3 , min( 3b^2 - 8a c , 3b^4 + 16a^2 c^2 + 16a^2 b d - 16a b^2 c - 64a^3 e ) ) ) - 1/2 ) 
  ) 
  sqrt(3 ( 3b^2 - 8a c + 2a ((-1-sqrt(-3))/2) root(3, 4 ( 2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e + sqrt((2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e)^2 - 4(c^2 - 3b d + 12a e)^3) )) + 2a ((-1+sqrt(-3))/2) root(3, 4 ( 2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e - sqrt((2c^3 - 9b c d + 27a d^2 + 27b^2 e - 72a c e)^2 - 4(c^2 - 3b d + 12a e)^3) )) )), 
  12a
)
$

你可以对外部文献或文中的标记进行引用，例如：

```typ
表格见 @tbl1，代码块见 @code1。
```

对应的渲染效果如下：

表格见 @tbl1，代码块见 @code1。

= Markdown 渲染

最后，使用 `cmarker` 库可以渲染 Markdown 文件内容：

```typ
#let md-content = read("index.md")
#cmarker.render(md-content, math: mitex, scope: scope)
```

更详细的使用示例请参考 `cmarker` 的官方文档。