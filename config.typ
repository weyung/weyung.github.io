#import "lib/typ2html/typ2html.typ" : *

#let footer-content = [
  2026 \~ Present    Carbon Typst Blog
]

#let tag-options = (
  "AI": (preset: "red", "icon": "/assets/icons/tag-lucide-bot.svg"),
  "Agent": (preset: "orange", "icon": "/assets/icons/tag-lucide-brain.svg"),
  "C": (preset: "yellow", "icon": "/assets/icons/tag-simple-c.svg"),
  "CTF": (preset: "green", "icon": "/assets/icons/tag-lucide-flag.svg"),
  "CVP": (preset: "teal", "icon": "/assets/icons/tag-lucide-key.svg"),
  "Code-server": (preset: "cyan", "icon": "/assets/icons/tag-simple-coder.svg"),
  "Crypto": (preset: "blue", "icon": "/assets/icons/tag-lucide-lock.svg"),
  "GPT": (preset: "indigo", "icon": "/assets/icons/tag-lucide-sparkles.svg"),
  "Golang": (preset: "purple", "icon": "/assets/icons/tag-simple-go.svg"),
  "Java": (preset: "pink", "icon": "/assets/icons/tag-lucide-coffee.svg"),
  "LLM": (preset: "orange", "icon": "/assets/icons/tag-lucide-cpu.svg"),
  "Linux": (preset: "red", "icon": "/assets/icons/tag-simple-linux.svg"),
  "Nginx": (preset: "orange", "icon": "/assets/icons/tag-simple-nginx.svg"),
  "PHP": (preset: "yellow", "icon": "/assets/icons/tag-simple-php.svg"),
  "Python": (preset: "green", "icon": "/assets/icons/tag-simple-python.svg"),
  "SSL": (preset: "teal", "icon": "/assets/icons/tag-lucide-shield-check.svg"),
  "Typst": (preset: "cyan", "icon": "/assets/icons/tag-simple-typst.svg"),
  "VSCode": (preset: "blue", "icon": "/assets/icons/tag-lucide-code.svg"),
  "WSL": (preset: "indigo", "icon": "/assets/icons/tag-lucide-terminal.svg"),
  "Web": (preset: "purple", "icon": "/assets/icons/tag-lucide-globe.svg"),
  "Windows": (preset: "pink", "icon": "/assets/icons/tag-lucide-layout-grid.svg"),
  "pwn": (preset: "red", "icon": "/assets/icons/tag-lucide-skull.svg"),
  "二进制安全": (preset: "red", "icon": "/assets/icons/tag-lucide-bug.svg"),
  "代理": (preset: "orange", "icon": "/assets/icons/tag-lucide-network.svg"),
  "信号与系统笔记": (preset: "yellow", "icon": "/assets/icons/tag-lucide-radio.svg"),
  "信息论": (preset: "green", "icon": "/assets/icons/tag-lucide-binary.svg"),
  "写作指南": (preset: "teal", "icon": "/assets/icons/tag-lucide-feather.svg"),
  "前端": (preset: "cyan", "icon": "/assets/icons/tag-lucide-layout-template.svg"),
  "博客搭建": (preset: "blue", "icon": "/assets/icons/tag-lucide-wrench.svg"),
  "复变函数": (preset: "indigo", "icon": "/assets/icons/tag-lucide-infinity.svg"),
  "学习": (preset: "purple", "icon": "/assets/icons/tag-lucide-graduation-cap.svg"),
  "抽象代数": (preset: "pink", "icon": "/assets/icons/tag-lucide-boxes.svg"),
  "数学": (preset: "purple", "icon": "/assets/icons/tag-lucide-calculator.svg"),
  "杂谈": (preset: "red", "icon": "/assets/icons/tag-lucide-coffee.svg"),
  "材料力学": (preset: "orange", "icon": "/assets/icons/tag-lucide-hammer.svg"),
  "格": (preset: "yellow", "icon": "/assets/icons/tag-lucide-grid-3x3.svg"),
  "汇编": (preset: "green", "icon": "/assets/icons/tag-lucide-microchip.svg"),
  "渗透": (preset: "teal", "icon": "/assets/icons/tag-lucide-sword.svg"),
  "生活": (preset: "cyan", "icon": "/assets/icons/tag-lucide-sun.svg"),
  "电影": (preset: "blue", "icon": "/assets/icons/tag-lucide-film.svg"),
  "算法": (preset: "indigo", "icon": "/assets/icons/tag-lucide-code-xml.svg"),
  "计算机": (preset: "purple", "icon": "/assets/icons/tag-lucide-monitor.svg"),
  "计算机网络": (preset: "pink", "icon": "/assets/icons/tag-lucide-server.svg"),
  "计组": (preset: "blue", "icon": "/assets/icons/tag-lucide-hard-drive.svg"),
  "论文": (preset: "red", "icon": "/assets/icons/tag-lucide-book-open.svg"),
  "配置指南": (preset: "orange", "icon": "/assets/icons/tag-lucide-settings.svg"),
  "静态分析": (preset: "yellow", "icon": "/assets/icons/tag-lucide-search-code.svg"),
  "面试": (preset: "green", "icon": "/assets/icons/tag-lucide-users.svg"),
  "高数": (preset: "teal", "icon": "/assets/icons/tag-lucide-trending-up.svg"),
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
  favicon: "/assets/avatar.png",
  tag-options: tag-options,
  post-scripts: (
    "/assets/core/render-code.js",
    "/assets/core/theme.js",
    "/assets/core/post-nav-switch.js",
    "/assets/core/home-search.js?v=20260710-search-fixes",
  ),
  page-scripts: (
    "/assets/core/render-code.js",
    "/assets/core/theme.js",
    "/assets/core/post-nav-switch.js",
    "/assets/core/post-card-click.js",
    "/assets/core/home-search.js?v=20260710-search-fixes",
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
