#import "html-guard.typ": html-guard

#let make-nav(site-title, links, post-title: none) = if links != none {
  let nav-lower-title = if post-title != none { post-title } else { site-title }

  html.div(class: "nav-shell", {
    html.nav({
      html.elem("button", attrs: (
        class: "nav-menu-switch",
        type: "button",
        "aria-label": "打开导航",
      ))[]

      html.div(class: "nav-title", site-title)

      html.div(class: "nav-body has-post-title", {
        html.div(class: "nav-body-upper", {
          html.div(class: "nav-body-upper-title", site-title)
          html.div(class: "nav-body-upper-links", {
            for (href, name) in links {
              html.a(href: href, name)
            }
          })
        })

        html.div(class: "nav-body-lower", nav-lower-title)
      })

      html.elem("button", attrs: (
        class: "nav-theme-switch",
        type: "button",
        "aria-label": "切换主题",
      ))[]
    })

    html.div(class: "nav-sidebar-backdrop")
    html.aside(class: "nav-sidebar", {
      for (href, name) in links {
        html.a(class: "nav-sidebar-item", href: href, name)
      }
    })
  })
}

#let make-header(links, site-title) = context {
  html-guard(() => {
    html.header(
      html.div(class: "site-header", {
        make-nav(site-title, links)
      })
    )
  })
}

#let make-post-header(links, site-title, title) = context {
  html-guard(() => {
    html.header({
      html.div(class: "site-header", {
        make-nav(site-title, links, post-title: title)
      })
    })

    html.div(class: "post-header", {
      html.div(class: "post-header-inner", {
        html.h1(title)
      })
    })
  })
}

#let make-post-footer(previous-post: none, next-post: none, footer-content: none) = context {
  html-guard(() => {
    if previous-post != none or next-post != none [
      #html.div(class: "post-neighbors", {
        html.div(class: "post-neighbors-inner", {
          if previous-post != none {
            html.a(class: "post-neighbor", href: previous-post.url, {
              html.div(class: "post-neighbor-top", "上一篇")
              html.p(class: "post-neighbor-title", str(previous-post.title))
            })
          }
          if next-post != none {
            html.a(class: "post-neighbor", href: next-post.url, {
              html.div(class: "post-neighbor-top", "下一篇")
              html.p(class: "post-neighbor-title", str(next-post.title))
            })
          }
        })
      })
    ]

    html.footer({
      html.div(class: "post-footer", {
        if footer-content != none {
          footer-content
        }
      })
    })
  })
}

#let render-post-license(author: none, url: none) = context {
  html-guard(() => {
    html.div(class: "post-license", {
      if author != none {
        html.div(class: "post-license-item", {
          html.span(class: "post-license-label", "文章作者")
          html.span(author)
        })
      }
      if url != none {
        html.div(class: "post-license-item", {
          html.span(class: "post-license-label", "文章链接")
          html.a(href: url, url)
        })
      }
      html.div(class: "post-license-item", {
        html.span(class: "post-license-label", "许可协议")
        html.a(
          href: "https://creativecommons.org/licenses/by-nc-sa/4.0/",
          target: "_blank",
          rel: ("noopener", "noreferrer"),
          "CC BY-NC-SA 4.0",
        )
      })
    })
  })
}

#let make-page-footer(footer-content: none) = context {
  html-guard(() => {
    html.elem("footer", attrs: (class: "page-footer"))[
      #if footer-content != none [#footer-content]
    ]
  })
}
