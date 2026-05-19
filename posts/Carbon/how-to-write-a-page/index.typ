#import "../../../config.typ": *

#show: template-post.with(
  title: "如何调整除了博客文章之外的页面",
  description: "本文主要介绍在 Carbon Typst Blog 中调整除了博客文章之外的页面（例如分类页、标签页、归档页等）的步骤和注意事项。",
  tags: ("Typst", "配置指南",),
  category: "博客的构建和调整",
  date: datetime(year: 2000, month: 3, day: 18)
)

在 Carbon Typst Blog 中，除了博客文章页面之外，还有一些其他类型的页面，例如分类页、标签页、归档页等。这些页面的模板和样式与博客文章页面是分开的，因此你可以通过调整这些页面的模板来定制它们的外观和功能。这些页面对应的 `index.typ` 文件可以参考 #link("/posts/introduction/")[介绍]。

和博客文章不同，这些页面在构建时需要接受命令行参数的控制，从而让构建脚本可以正确渲染这些界面。Carbon Typst Blog 提供了一套查询输入的工具函数，帮助你从命令行参数中获取相关信息，例如当前页面的标签、分类、页码等。这些工具函数定义在 `lib/typ2html/sys-input.typ` 文件中，你可以在这些函数的基础上进行调整和扩展，以满足你的需求。

以下是所有可用的查询输入工具函数：

== 基础函数
- `query-input(key, default: none)` : 获取指定键的命令行参数值，如果没有提供则返回默认值。
- `query-posts()` : 获取博客文章数据的 JSON 对象，其中包含了所有博客文章的相关信息，*按照时间升序排序*，格式如下：
  ```json
  [
    {
      "slug": "introduction",
      "url": "/posts/introduction/",
      "title": "Carbon Typst Blog 介绍",
      "description": "本文主要介绍 Carbon Typst Blog 的基本功能和配置方式。",
      "tags": ["博客搭建"],
      "category": "",
      "date": "2026-03-17"
    },
  ]
  ```
- `query-slugs()` : 获取标签和分类的 slug 数据的 JSON 对象，其中包含了标签和分类名称与 slug 的映射关系，格式如下：
  ```json
  {
    "tags": {
      "博客搭建": "博客搭建",
      "配置指南": "配置指南",
      "写作指南": "写作指南",
      "Typst": "typst"
    }, "categories": {
      "测试": "测试"
    }
  }
  ```

== 标签和分类相关函数

- `query-route-tag(default: "")` : 获取当前页面的标签 slug，在标签页中使用。
- `query-route-category(default: "")` : 获取当前页面的分类 slug，在分类页中使用。
- `query-tag-slug-of(value)` : 获取指定标签的 slug。
- `query-category-slug-of(value)` : 获取指定分类的 slug。

== 分页相关函数

- `query-route-page(default: 1)` : 获取当前页面的页码，默认为 1。
- `query-route-page-size(default: 10)` : 获取当前页面的每页显示数量，默认为 10。
- `query-page-bounds(total, page: 1, page-size: 10)` : 根据总条目数、当前页码和每页显示数量计算分页信息，返回一个包含当前页码、每页显示数量、总页数、起始索引和结束索引的对象。

使用上述函数，你就可以在分类页、标签页等页面中获取到当前页面的标签或分类信息，以及分页信息，从而根据这些信息来渲染页面内容。以下是标签页 `pages/tags/[tag]/index.typ` 的示例代码：

```typ
#import "../../../config.typ": *
// 获取博客文章数据和当前页面的标签信息 
#let posts = query-posts()
#let current = query-route-tag()
#let route-page = query-route-page()
#let route-page-size = query-route-page-size(default: 10)

// 设置页面标题和描述
#show: template-page.with(
  title: if current == "" { "标签详情" } else { "标签：" + current },
  description: "标签详情页面",
)

// 渲染页面的面包屑导航
#render-page-breadcrumb(
  items: (("/", "首页"), ("/tags/", "标签")),
)

// 展示当前标签
= #current

// 根据当前标签过滤博客文章
#let matched = posts.filter(post => post.tags.any(tag => tag == current))

// 根据过滤后的文章数量和分页信息计算分页边界
#let bounds = query-page-bounds(matched.len(), page: route-page, page-size: route-page-size)
#let current-page = int(bounds.at("page", default: 1))
#let total-pages = int(bounds.at("total-pages", default: 1))
#let start-index = int(bounds.at("start-index", default: 0))
#let end-index = int(bounds.at("end-index", default: -1))

// 渲染文章列表
#if matched.len() == 0 {
  html.div(class: "error-block", {
    "暂无文章"
  })
} else {
  html.div(class: "posts-grid", {
    for i in range(end-index, start-index - 1, step: -1) {
      let post = matched.at(i)
      let date-parts = post.date.split("-")
      let post-date-text = if date-parts.len() == 3 {
        format-post-date(datetime(
          year: int(date-parts.at(0)),
          month: int(date-parts.at(1)),
          day: int(date-parts.at(2)),
        ))
      } else {
        post.date
      }
      html.elem("div", attrs: (
        class: "post-card",
        "data-post-url": post.url,
      ), {
        html.div(class: "post-title", {
          html.a(class: "post-card-link", href: post.url, post.title)
        })
        html.div(class: "post-description", {
          post.description
        })
        if post.tags.len() != 0 {
          html.div(class: "post-card-tags", {
            for tag in post.tags {
              render-tag-link(tag, href: "/tags/" + query-tag-slug-of(tag) + "/")
            }
          })
        }
        html.div(class: "post-date", {
          post-date-text
        })
      })
    }
  })

  render-pagination-nav(
    "/tags/" + query-tag-slug-of(current) + "/",
    current-page,
    total-pages,
    aria-label: "标签分页",
  )
}
```

如果你需要深度修改这些页面的结构和样式，可以直接编辑对应的 `index.typ` 文件，并使用上述查询输入工具函数来获取必要的数据和信息。通过这种方式，你可以灵活地定制分类页、标签页等页面的内容和布局，以满足你的需求。