#import "../../../config.typ": *

#show: template-post.with(
  title: "如何编写一篇博客文章",
  description: "本文主要介绍在 Carbon Typst Blog 中添加和编写博客文章的步骤和注意事项。",
  tags: ("Typst", "写作指南"),
  category: "如何编写博客文章",
  date: datetime(year: 2000, month: 3, day: 18)
)

= 创建新文章

在 Carbon Typst Blog 中，每篇博客文章都是一个独立的 `index.typ` 文件，位于 `posts` 目录下。要创建一篇新的博客文章，你需要在 `posts` 目录中创建一个新的文件夹，并在其中添加一个 `index.typ` 文件。例如，本文的路径是 `posts/how-to-write-a-post/index.typ`。

= 引入依赖

在 `index.typ` 文件的开头，你需要引入对根目录下的 `config.typ` 文件的引用，以及任何你需要使用的库或模块：

```typ
// 文件路径可能需要根据实际情况调整
#import "../../config.typ": *
```

然后，需要通过 ```typ show``` 规则引入博客文章的模板。这个模板会在 HTML 导出时被使用，并且会自动填充文章的标题、描述、标签和日期等元信息：

```typ
#show: template-post.with(
  title: "如何编写一篇博客文章",
  description: "本文主要介绍在 Carbon Typst Blog 中添加和编写博客文章的步骤和注意事项。",
  tags: ("Typst", "写作指南"),
  date: datetime(year: 2026, month: 3, day: 18),
  category: "写作指南"
)
```

其中，标题、描述和日期是必须的，而标签和分类则是可选的。你可以根据需要添加更多的标签或分类，以便更好地组织和展示你的博客文章。

#warning(title: "注意！")[
  如果你不熟悉 Typst 的语法，在你的文章只有一个标签时，需要将标签放在一个元组中，例如 `tags: ("Typst",)`，而不是 `tags: ("Typst")`，后者会被解析为一个字符串而不是一个元组，从而导致标签无法正确显示。
]

在引入模板之后，你就可以开始编写博客文章的内容了。你可以使用 Typst 的各种文本格式化功能来丰富你的文章内容，例如标题、段落、列表、图片等。有关更多的内容编写技巧和示例，请参考 #link("/posts/typst-example/")[Typst 功能展示]。

= PDF 预览

除了通过 HTML 导出之外，Carbon Typst Blog 还支持通过 PDF 预览来查看你的博客文章。如果你需要调整 PDF 预览时的显示效果，请在 `config.typ` 中进行相应的修改。具体内容可以参考 #link("/posts/config-typ/")[配置文件说明]。

需要注意，数学公式或 `auto-frame()` 包裹的图像都是通过 SVG 导出到 HTML 中的，因此其行为会和 PDF 上的渲染结果相符，字体大小、颜色等设置也会在 HTML 导出时生效。不过有一个例外：页面在选择暗色模式时，会*将图像的颜色反转*（使用的 CSS Filter 是 ` invert(1) hue-rotate(180deg)`）。

= 结语

通过以上的步骤，你就可以在 Carbon Typst Blog 中成功创建和编写一篇新的博客文章了！

#figure(
  image("/assets/image.png"),
  caption: [本文的编写示例图]
)