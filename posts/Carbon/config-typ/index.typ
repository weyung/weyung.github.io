#import "../../../config.typ": *

#show: template-post.with(
  title: "配置文件说明",
  description: "本文主要介绍在 Carbon Typst Blog 中配置文件的作用和使用方法，以及如何通过配置文件来定制博客的外观和功能。",
  tags: ("配置指南",),
  category: "博客的构建和调整",
  date: datetime(year: 2000, month: 3, day: 18)
)

本文主要介绍 `config.typ` 和 `site.config.json` 这两个配置文件的作用和使用方法，以及如何通过它们来定制 Carbon Typst Blog 的外观和功能。

= `config.typ`

`config.typ` 是 Carbon Typst Blog 的主要配置文件，位于项目的根目录下。它是一个 Typst 文件，定义了博客的全局设置、模板和一些辅助函数。通过修改 `config.typ`，你可以定制博客的标题、导航链接、标签样式、页脚内容等。

以下是可能的 `config.typ` 文件内容：

```typ
// 引入 typ2html 库，提供 HTML 导出相关的功能和模板
#import "lib/typ2html/typ2html.typ" : *

// 定义页脚内容，可以在这里添加版权信息、联系方式等
#let footer-content = [
  2026 \~ Present Carbon Typst Blog
]

// 定义标签的样式和图标，可以根据需要添加更多的标签选项
#let tag-options = (
  "博客搭建": (preset: "cyan", "icon": "/assets/icons/rocket.svg"),
  "Typst": ("preset": "teal", "icon": "/assets/icons/pen.svg"),
  "写作指南": ("preset": "blue", "icon": "/assets/icons/edit.svg"),
  "配置指南": ("preset": "green", "icon": "/assets/icons/settings.svg"),
)

// 将标签选项应用到标签链接和标签卡片的渲染函数中，使其在博客中生效
// 这一部分无需修改，除非你需要自定义标签的渲染方式
#let render-tag-link = render-tag-link.with(tag-options: tag-options)
#let render-tag-card = render-tag-card.with(tag-options: tag-options)

// 定义博客的模板，包括站点标题、导航链接、语言、页脚内容等
#let templates = make-templates(
  // 站点标题，将显示在浏览器标签页和博客的头部
  site-title: "Carbon Typst Blog",
  // 导航链接，定义博客的主导航菜单，可以根据需要添加或修改链接
  header-links: (
    "/": "首页",
    "/categories/": "分类",
    "/tags/": "标签",
    "/archive/": "归档",
    "/about/": "关于",
  ),
  // 博客的语言设置，影响文本的排版和一些默认的文本内容
  lang: "zh",
  // 页脚内容，将显示在博客的底部，可以使用 HTML 或 Typst 的文本格式化功能
  footer-content: footer-content,
  // 标签选项，将在博客中使用定义的标签样式和图标
  tag-options: tag-options,
  // 自定义 CSS 文件，可以在这里添加你自己的样式来定制博客的外观
  custom-css: (
    "/assets/custom.css",
  ),
  // 自定义 JavaScript 文件，可以在这里添加你自己的脚本来增强博客的功能
  custom-script: (
    
  )
)

// 从模板中提取出文章模板和页面模板，供博客文章和页面使用
#let template-page = templates.page
#let template-post(..args) = {
  // 你可以在这里自定义 PDF 预览的效果
  // 以下是一些示例设置，你可以根据需要进行调整
  set page(height: auto, width: 30cm)
  set text(16pt, font: ("IBM Plex Sans SC"), lang: "zh")
  show raw: text.with(font: ("Zed Plex Mono", "IBM Plex Sans SC"))
  show math.equation: set text(16pt)
  set table(inset: 8pt)
  set grid(inset: 8pt)

  (templates.post)(..args)
}

```

其中，标签支持的颜色预设为：`gray`，`cool-gray`，`warm-gray`，`red`，`magenta`，`purple`，`blue`，`cyan`，`teal` 和 `green`。标签的图标应该是一个 SVG 图像的 URL 地址，你可以使用博客中提供的图标，也可以使用你自己的图标。你可以在 #link("https://carbondesignsystem.com/elements/icons/library/")[这个图标库] 中下载到符合 Carbon Design System 设计规范的 SVG 图标，或者使用其他来源的图标，只要它们是 SVG 格式的即可。你可以在定义标签选项时使用这些预设颜色，或者在 `lib/typ2html/tag.typ` 中自定义颜色信息。

= `site.config.json`

`site.config.json` 是一个可选的 JSON 配置文件，位于项目的根目录下。它主要用于存储一些需要在博客运行时访问的配置信息。目前 `site.config.json` 中的配置项包括：

```json
{
  "siteTitle": "Carbon Typst Blog",
  "siteUrl": "https://example.com",
  "author": "Carbon Typst Blog",
  "description": "Carbon Typst Blog RSS Feed",
  "language": "zh-cn"
}
```

其中，`siteTitle` 是博客的标题，`siteUrl` 是博客的 URL 地址，`author` 是博客的作者名称，`description` 是博客的描述信息，`language` 是博客的语言设置。你可以根据需要修改这些配置项来定制你的博客。需要注意的是，`site.config.json` 中的配置项会在博客运行时被读取并且在生成 RSS Feed 和其他需要使用这些信息的地方生效，因此请确保这些信息的准确性和完整性。