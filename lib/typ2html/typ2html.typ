#import "block.typ": quote, note, success, warning, error
#import "tag.typ": render-tag-link, render-tag-card
#import "breadcrumb.typ": render-page-breadcrumb
#import "pagination.typ": render-pagination-nav
#import "sys-input.typ": query-input, query-posts, query-slugs, query-route-tag, query-route-category, query-route-page, query-route-page-size, query-tag-slug-of, query-category-slug-of, query-page-bounds
#import "layout.typ": make-nav, make-header, make-post-header, make-post-footer, make-page-footer
#import "divider.typ": divider
#import "html-guard.typ": html-guard
#import "math.typ": auto-frame
#import "metadata.typ": metadata

#let make-theme-preload-script() = html.script(
  type: "text/javascript",
  "(function(){var key='typ-blog-theme';var theme=null;try{var stored=localStorage.getItem(key);if(stored==='gray-10'||stored==='gray-90'||stored==='gray-100'||stored==='white'){theme=stored;}}catch(_){ }if(!theme){theme=window.matchMedia('(prefers-color-scheme: dark)').matches?'gray-90':'gray-10';}document.documentElement.setAttribute('data-theme',theme);var bg=theme==='gray-90'?'#262626':theme==='gray-100'?'#161616':theme==='white'?'#ffffff':'#f4f4f4';document.documentElement.style.backgroundColor=bg;})();",
)

#let post-date-storage-format = "[year]-[month]-[day]"
#let post-date-display-format = "[year] 年 [month padding:none] 月 [day padding:none] 日"
#let format-post-date(date) = date.display(post-date-display-format)

#let render-footnotes() = context {
  html-guard(() => {
    let footnotes = query(footnote)
    if footnotes.len() != 0 {
      html.elem("section", attrs: (role: "doc-endnotes"))[
        #html.hr()
        #html.ol({
          for (i, it) in footnotes.enumerate() {
            let number = str(i + 1)
            let fn-id = "fn-" + number
            let ref-id = "fnref-" + number

            html.li(
              class: "footnote-index",
              id: fn-id,
              it.body + html.a(class: "footnote-ref-link", href: "#" + ref-id),
            )
          }
        })
      ]
    }
  })
}

#let render-meta(tags, category, date-string, tag-options: (:)) = context {
  html-guard(() => {
    html.div(class: "post-meta", {
      if tags != none and tags.len() != 0 {
        html.div(class: "post-tag", {
          html.span(class: "post-tag-desc", "标签")
          html.span(class: "post-tag-group", {
            for tag in tags {
              render-tag-link(tag, href: "/tags/" + query-tag-slug-of(tag) + "/", tag-options: tag-options)
            }
          })
        })
      }
      html.div(class: "post-time", {
        html.span(class: "post-time-desc", "日期")
        html.span(date-string)
      })
      if category != none and category != "" {
        html.div(class: "post-category", {
          html.span(class: "post-category-desc", "分类")
          html.a(class: "post-category-link", href: "/categories/" + query-category-slug-of(category) + "/", category)
        })
      }
    })
  })
}

#let typ2html-base(
  header-links: none,
  site-title: "Typst Blog",
  title: "Carbon & Typst Blog",
  lang: "en",
  css: (
    "https://cdn.jsdelivr.net/npm/@ibm/plex-sans@1.1.0/css/ibm-plex-sans-all.min.css",
    "https://cdn.jsdelivr.net/npm/@ibm/plex-mono@1.1.0/css/ibm-plex-mono-all.min.css",
    "/assets/core/colors.css",
    "/assets/core/main.css",
  ),
  scripts: (),
  custom-css: (),
  custom-script: (),
  description: "",
  include-description-meta: false,
  website-url: query-input("website-url", default: none),
  author: query-input("author", default: none),
  include-rss-link: false,
  feed-path: "/rss.xml",
  canonical-path: none,
  date-meta: none,
  head-extra: none,
  header-node: none,
  main-node: none,
  footer-node: none,
  content
) = context {
  html-guard(() => {
    import "raw.typ": template-raw
    import "grid.typ": template-grids
    import "math.typ": template-math
    import "refs.typ": template-refs
    import "notes.typ": template-notes
    import "links.typ": template-links
    import "figures.typ": template-figures
    import "table.typ": template-table
    import "text-color.typ": template-text-color

    show: template-text-color
    show: template-raw
    show: template-math
    show: template-refs
    show: template-notes
    show: template-figures
    show: template-links
    show: template-grids
    show: template-table

    set text(lang: lang)

    html.html(
      lang: lang,
      {
        html.head({
          metadata(
            title: title,
            author: author,
            description: if include-description-meta { description } else { none },
            lang: lang,
            date: date-meta,
            website-title: site-title,
            website-url: website-url,
            canonical-path: canonical-path,
            include-rss-link: include-rss-link,
            feed-path: feed-path,
          )

          if head-extra != none {
            head-extra
          }

          html.link(rel: "preconnect", href: "https://cdn.jsdelivr.net")
          html.link(rel: "dns-prefetch", href: "https://cdn.jsdelivr.net")

          make-theme-preload-script()

          for (css-link) in css {
            html.link(rel: "stylesheet", href: css-link)
          }
          for (css-link) in custom-css {
            html.link(rel: "stylesheet", href: css-link)
          }
          for (js-src) in scripts {
            html.script(type: "module", src: js-src)
          }
          for (js-src) in custom-script {
            html.script(type: "module", src: js-src)
          }
        })

        html.body({
          html.div(class: "page-shell", {
            if header-node != none {
              header-node
            }
            if main-node != none {
              main-node
            }
            if footer-node != none {
              footer-node
            }
          })
        })
      },
    )
  }, fallback: () => {
    content
  })
}

#let typ2html-post(
  header-links: none,
  site-title: "Typst Blog",
  title: "Carbon & Typst Blog",
  lang: "en",

  css: (
    "https://cdn.jsdelivr.net/npm/@ibm/plex-sans@1.1.0/css/ibm-plex-sans-all.min.css",
    "https://cdn.jsdelivr.net/npm/@ibm/plex-mono@1.1.0/css/ibm-plex-mono-all.min.css",
    "/assets/core/colors.css",
    "/assets/core/main.css",
  ),
  scripts: (
    "/assets/core/render-code.js",
    "/assets/core/theme.js",
    "/assets/core/post-nav-switch.js",
  ),
  custom-css: (),
  custom-script: (),
  footer-content: none,
  tag-options: (:),

  tags: (),
  category: "",
  date: datetime.today(),
  description: "",
  website-url: query-input("website-url", default: none),
  author: query-input("author", default: none),
  emit-post-meta: query-input("emit-post-meta", default: none),

  content,
) = {
  let json-escape(value) = {
    let s1 = str(value)
    let s2 = s1.replace("\\", "\\\\")
    let s3 = s2.replace("\"", "\\\"")
    let s4 = s3.replace("\n", "\\n")
    let s5 = s4.replace("\r", "\\r")
    s5.replace("\t", "\\t")
  }

  let json-string(value) = "\"" + json-escape(value) + "\""
  let date-string = date.display(post-date-storage-format)
  let date-string-localized = format-post-date(date)
  let tags-json = "[" + tags.map(tag => json-string(tag)).join(",") + "]"
  let post-meta-json = "{" + "\"title\":" + json-string(title) + "," + "\"description\":" + json-string(description) + "," + "\"category\":" + json-string(category) + "," + "\"tags\":" + tags-json + "," + "\"date\":" + json-string(date-string) + "}"

  if emit-post-meta != none {
    post-meta-json
  } else {
    let page-path = query-input("page-path", default: "")
    let all-posts = query-posts()

    let matched-indexes = range(all-posts.len()).filter(i => all-posts.at(i).slug == page-path)
    let current-index = matched-indexes.at(0, default: none)

    let previous-post = if current-index == none or current-index == 0 { none } else { all-posts.at(current-index - 1) }
    let next-post = if current-index == none or current-index + 1 >= all-posts.len() { none } else { all-posts.at(current-index + 1) }

    typ2html-base(
      header-links: header-links,
      site-title: site-title,
      title: title,
      lang: lang,
      css: css,
      scripts: scripts,
      custom-css: custom-css,
      custom-script: custom-script,
      description: description,
      include-description-meta: true,
      website-url: website-url,
      author: author,
      canonical-path: "/posts/" + page-path,
      date-meta: date,
      header-node: make-post-header(header-links, site-title, title),
      main-node: html-guard(() => {
        html.article({
          html.section({
            content
            render-footnotes()
            render-meta(tags, category, date-string-localized, tag-options: tag-options)
          })
        })
      }),
      footer-node: make-post-footer(previous-post: previous-post, next-post: next-post, footer-content: footer-content),
      content
    )
  }
}

#let typ2html-page(
  header-links: none,
  site-title: "Typst Blog",
  title: "Carbon & Typst Blog",
  lang: "en",
  css: (
    "https://cdn.jsdelivr.net/npm/@ibm/plex-sans@1.1.0/css/ibm-plex-sans-all.min.css",
    "https://cdn.jsdelivr.net/npm/@ibm/plex-mono@1.1.0/css/ibm-plex-mono-all.min.css",
    "/assets/core/colors.css",
    "/assets/core/main.css",
    "/assets/core/pages.css",
  ),
  scripts: (
    "/assets/core/theme.js",
    "/assets/core/post-nav-switch.js",
    "/assets/core/post-card-click.js",
  ),
  custom-css: (),
  custom-script: (),
  footer-content: none,
  page-wrapper: content => html-guard(() => {
    html.main({
      content
    })
  }),
  description: "",
  website-url: query-input("website-url", default: none),
  author: query-input("author", default: none),
  content,
) = {
  typ2html-base(
    header-links: header-links,
    site-title: site-title,
    title: title,
    lang: lang,
    css: css,
    scripts: scripts,
    custom-css: custom-css,
    custom-script: custom-script,
    description: description,
    include-description-meta: true,
    website-url: website-url,
    author: author,
    include-rss-link: true,
    canonical-path: query-input("page-path", default: ""),
    date-meta: datetime.today(),
    head-extra: {
      html.meta(name: "tags", content: "none")
      html.meta(name: "category", content: "")
    },
    header-node: html-guard(() => make-header(header-links, site-title)),
    main-node: html-guard(() => page-wrapper(content)),
    footer-node: html-guard(() => make-page-footer(footer-content: footer-content)),
    content
  )
}

#let make-templates(
  header-links: none,
  site-title: "Typst Blog",
  title: "Carbon & Typst Blog",
  lang: "en",
  custom-css: (),
  custom-script: (),
  footer-content: none,
  description: "",
  website-url: query-input("website-url", default: none),
  author: query-input("author", default: none),
  tag-options: (:),

  post-css: (
    "https://cdn.jsdelivr.net/npm/@ibm/plex-sans@1.1.0/css/ibm-plex-sans-all.min.css",
    "https://cdn.jsdelivr.net/npm/@ibm/plex-mono@1.1.0/css/ibm-plex-mono-all.min.css",
    "/assets/core/colors.css",
    "/assets/core/main.css",
  ),
  post-scripts: (
    "/assets/core/render-code.js",
    "/assets/core/theme.js",
    "/assets/core/post-nav-switch.js",
  ),

  page-css: (
    "https://cdn.jsdelivr.net/npm/@ibm/plex-sans@1.1.0/css/ibm-plex-sans-all.min.css",
    "https://cdn.jsdelivr.net/npm/@ibm/plex-mono@1.1.0/css/ibm-plex-mono-all.min.css",
    "/assets/core/colors.css",
    "/assets/core/main.css",
    "/assets/core/pages.css",
  ),
  page-scripts: (
    "/assets/core/theme.js",
    "/assets/core/post-nav-switch.js",
    "/assets/core/post-card-click.js",
  ),
  page-wrapper: content => html-guard(() => {
    html.main({
      html.div(class: "pages-container", {
        html.div(class: "pages-container-inner", {
          content
        })
      })
    })
  }),
) = (
  post: typ2html-post.with(
    header-links: header-links,
    site-title: site-title,
    title: title,
    lang: lang,
    css: post-css,
    scripts: post-scripts,
    custom-css: custom-css,
    custom-script: custom-script,
    footer-content: footer-content,
    description: description,
    website-url: website-url,
    author: author,
    tag-options: tag-options,
  ),
  page: typ2html-page.with(
    header-links: header-links,
    site-title: site-title,
    title: title,
    lang: lang,
    css: page-css,
    scripts: page-scripts,
    custom-css: custom-css,
    custom-script: custom-script,
    footer-content: footer-content,
    page-wrapper: page-wrapper,
    description: description,
    website-url: website-url,
    author: author,
  )
)
