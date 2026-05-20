#import "lib/typ2html/typ2html.typ" : *

#let footer-content = [
  2026 \~ Present    Carbon Typst Blog
]

#let tag-options = (
  "AI": (preset: "red", "icon": "/assets/icons/rocket.svg"),
  "Agent": (preset: "orange", "icon": "/assets/icons/pen.svg"),
  "C": (preset: "yellow", "icon": "/assets/icons/edit.svg"),
  "CTF": (preset: "green", "icon": "/assets/icons/settings.svg"),
  "CVP": (preset: "teal", "icon": "/assets/icons/hashtag.svg"),
  "Code-server": (preset: "cyan", "icon": "/assets/icons/folder.svg"),
  "Crypto": (preset: "blue", "icon": "/assets/icons/information--filled.svg"),
  "GPT": (preset: "indigo", "icon": "/assets/icons/checkmark--filled.svg"),
  "Golang": (preset: "purple", "icon": "/assets/icons/rocket.svg"),
  "Java": (preset: "pink", "icon": "/assets/icons/pen.svg"),
  "LLM": (preset: "gray", "icon": "/assets/icons/edit.svg"),
  "Linux": (preset: "red", "icon": "/assets/icons/settings.svg"),
  "Nginx": (preset: "orange", "icon": "/assets/icons/hashtag.svg"),
  "PHP": (preset: "yellow", "icon": "/assets/icons/folder.svg"),
  "Python": (preset: "green", "icon": "/assets/icons/information--filled.svg"),
  "SSL": (preset: "teal", "icon": "/assets/icons/checkmark--filled.svg"),
  "Typst": (preset: "cyan", "icon": "/assets/icons/rocket.svg"),
  "VSCode": (preset: "blue", "icon": "/assets/icons/pen.svg"),
  "WSL": (preset: "indigo", "icon": "/assets/icons/edit.svg"),
  "Web": (preset: "purple", "icon": "/assets/icons/settings.svg"),
  "Windows": (preset: "pink", "icon": "/assets/icons/hashtag.svg"),
  "pwn": (preset: "gray", "icon": "/assets/icons/folder.svg"),
  "二进制安全": (preset: "red", "icon": "/assets/icons/information--filled.svg"),
  "代理": (preset: "orange", "icon": "/assets/icons/checkmark--filled.svg"),
  "信号与系统笔记": (preset: "yellow", "icon": "/assets/icons/rocket.svg"),
  "信息论": (preset: "green", "icon": "/assets/icons/pen.svg"),
  "写作指南": (preset: "teal", "icon": "/assets/icons/edit.svg"),
  "前端": (preset: "cyan", "icon": "/assets/icons/settings.svg"),
  "博客搭建": (preset: "blue", "icon": "/assets/icons/hashtag.svg"),
  "复变函数": (preset: "indigo", "icon": "/assets/icons/folder.svg"),
  "学习": (preset: "purple", "icon": "/assets/icons/information--filled.svg"),
  "抽象代数": (preset: "pink", "icon": "/assets/icons/checkmark--filled.svg"),
  "数学": (preset: "gray", "icon": "/assets/icons/rocket.svg"),
  "杂谈": (preset: "red", "icon": "/assets/icons/pen.svg"),
  "材料力学": (preset: "orange", "icon": "/assets/icons/edit.svg"),
  "格": (preset: "yellow", "icon": "/assets/icons/settings.svg"),
  "汇编": (preset: "green", "icon": "/assets/icons/hashtag.svg"),
  "渗透": (preset: "teal", "icon": "/assets/icons/folder.svg"),
  "生活": (preset: "cyan", "icon": "/assets/icons/information--filled.svg"),
  "电影": (preset: "blue", "icon": "/assets/icons/checkmark--filled.svg"),
  "算法": (preset: "indigo", "icon": "/assets/icons/rocket.svg"),
  "计算机": (preset: "purple", "icon": "/assets/icons/pen.svg"),
  "计算机网络": (preset: "pink", "icon": "/assets/icons/edit.svg"),
  "计组": (preset: "gray", "icon": "/assets/icons/settings.svg"),
  "论文": (preset: "red", "icon": "/assets/icons/hashtag.svg"),
  "配置指南": (preset: "orange", "icon": "/assets/icons/folder.svg"),
  "静态分析": (preset: "yellow", "icon": "/assets/icons/information--filled.svg"),
  "面试": (preset: "green", "icon": "/assets/icons/checkmark--filled.svg"),
  "高数": (preset: "teal", "icon": "/assets/icons/rocket.svg"),
)

#let render-tag-link = render-tag-link.with(tag-options: tag-options)
#let render-tag-card = render-tag-card.with(tag-options: tag-options)

#let templates = make-templates(
  site-title: "weyung's Blog",
  header-links: (
    "/": "首页",
    "/categories/": "分类",
    "/tags/": "标签",
    "/archive/": "归档",
    "/links/": "友链",
    "/about/": "关于",
  ),
  title: "Typst Blog",
  lang: "zh",
  footer-content: footer-content,
  tag-options: tag-options,
  page-scripts: (
    "/assets/core/render-code.js",
    "/assets/core/theme.js",
    "/assets/core/post-nav-switch.js",
    "/assets/core/post-card-click.js",
  ),
  custom-css: (
    "/assets/custom.css",
    "/assets/custom-toc.css",
  ),
  custom-script: (
    "/assets/custom-toc.js",
  )
)

#let template-page = templates.page
#let template-post(..args) = {
  set par(justify: true)
  set page(height: auto, width: 30cm)
  set text(16pt, font: ("IBM Plex Sans SC"), lang: "zh")
  show raw: text.with(font: ("Zed Plex Mono", "IBM Plex Sans SC"))
  show math.equation: set text(16pt)
  set table(inset: 8pt)
  set grid(inset: 8pt)

  (templates.post)(..args)
}
