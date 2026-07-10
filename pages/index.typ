#import "../config.typ": *
#let posts = query-posts()
#let route-page = query-route-page()
#let route-page-size = query-route-page-size(default: 10)
#let bounds = query-page-bounds(posts.len(), page: route-page, page-size: route-page-size)
#let current-page = int(bounds.at("page", default: 1))
#let total-pages = int(bounds.at("total-pages", default: 1))
#let start-index = int(bounds.at("start-index", default: 0))
#let end-index = int(bounds.at("end-index", default: -1))

#let display-post-date(post) = {
  let date-parts = post.date.split("-")
  if date-parts.len() == 3 {
    format-post-date(datetime(
      year: int(date-parts.at(0)),
      month: int(date-parts.at(1)),
      day: int(date-parts.at(2)),
    ))
  } else {
    post.date
  }
}

#let render-post-card(post) = {
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
      display-post-date(post)
    })
  })
}

#show: template-page.with(
  title: "首页",
  description: "站点首页",
)

#if route-page != 1 [
  = 文章列表
] else {
  html.div(class: "homepage-header-avatar-container", {
    html.img(class: "homepage-header-avatar", src: "/assets/avatar.png", alt: "Avatar")
  })
}

#if posts.len() == 0 {
  html.div(class: "error-block", {
    "暂无文章"
  })
} else {
  html.div(class: "posts-grid", {
    for i in range(end-index, start-index - 1, step: -1) {
      render-post-card(posts.at(i))
    }
  })

  render-pagination-nav("/", current-page, total-pages, aria-label: "首页分页")
}
