#import "lib/typ2html/typ2html.typ" : *

#let footer-content = [
  2026 \~ Present    Carbon Typst Blog
]

#let tag-options = (
  "博客搭建": (preset: "cyan", "icon": "/assets/icons/rocket.svg"),
  "Typst": ("preset": "teal", "icon": "/assets/icons/pen.svg"),
  "写作指南": ("preset": "blue", "icon": "/assets/icons/edit.svg"),
  "配置指南": ("preset": "green", "icon": "/assets/icons/settings.svg"),
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
