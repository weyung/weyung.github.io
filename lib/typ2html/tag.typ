#import "html-guard.typ": html-guard

#let tag-color-presets = (
  gray: (background: "tag-background-gray", color: "tag-color-gray", hover: "tag-hover-gray", border: "tag-border-gray"),
  cool-gray: (background: "tag-background-cool-gray", color: "tag-color-cool-gray", hover: "tag-hover-cool-gray", border: "tag-border-cool-gray"),
  warm-gray: (background: "tag-background-warm-gray", color: "tag-color-warm-gray", hover: "tag-hover-warm-gray", border: "tag-border-warm-gray"),
  red: (background: "tag-background-red", color: "tag-color-red", hover: "tag-hover-red", border: "tag-border-red"),
  orange: (background: "tag-background-orange", color: "tag-color-orange", hover: "tag-hover-orange", border: "tag-border-orange"),
  yellow: (background: "tag-background-yellow", color: "tag-color-yellow", hover: "tag-hover-yellow", border: "tag-border-yellow"),
  magenta: (background: "tag-background-magenta", color: "tag-color-magenta", hover: "tag-hover-magenta", border: "tag-border-magenta"),
  purple: (background: "tag-background-purple", color: "tag-color-purple", hover: "tag-hover-purple", border: "tag-border-purple"),
  pink: (background: "tag-background-pink", color: "tag-color-pink", hover: "tag-hover-pink", border: "tag-border-pink"),
  indigo: (background: "tag-background-indigo", color: "tag-color-indigo", hover: "tag-hover-indigo", border: "tag-border-indigo"),
  blue: (background: "tag-background-blue", color: "tag-color-blue", hover: "tag-hover-blue", border: "tag-border-blue"),
  cyan: (background: "tag-background-cyan", color: "tag-color-cyan", hover: "tag-hover-cyan", border: "tag-border-cyan"),
  teal: (background: "tag-background-teal", color: "tag-color-teal", hover: "tag-hover-teal", border: "tag-border-teal"),
  green: (background: "tag-background-green", color: "tag-color-green", hover: "tag-hover-green", border: "tag-border-green"),
)

#let default-tag-icon = "/assets/icons/hashtag.svg"

#let tag-option-of(tag, tag-options) = tag-options.at(str(tag), default: (:))

#let tag-preset-of(tag, tag-options) = {
  let option = tag-option-of(tag, tag-options)
  let selected = str(option.at("preset", default: "gray"))
  if tag-color-presets.keys().any(x => x == selected) {
    selected
  } else {
    "gray"
  }
}

#let tag-style-attr(tag, tag-options) = {
  let preset = tag-color-presets.at(tag-preset-of(tag, tag-options))
  (
    "--tag-background:var(--" + preset.background + ");" +
    "--tag-color:var(--" + preset.color + ");" +
    "--tag-background-hover:var(--" + preset.hover + ");" +
    "--tag-border:var(--" + preset.border + ");" +
    "--tag-border-hover:var(--" + preset.border + ");"
  )
}

#let tag-icon-src(tag, tag-options) = {
  let option = tag-option-of(tag, tag-options)
  str(option.at("icon", default: default-tag-icon))
}

#let render-tag-link(tag, href: none, tag-options: (:), full: false) = {
  let target = if href == none { "/tags/" + str(tag) } else { href }
  html-guard(() => {
    html.a(
      class: "post-tag-item tag-item-with-icon" + (if full {" tag-full"} else {""}),
      href: target,
      style: tag-style-attr(tag, tag-options),
      {
        html.span(
          class: "tag-icon",
          style: "mask-image:url(\"" + tag-icon-src(tag, tag-options) + "\");",
        )
        html.span(class: "tag-content", html.span(tag))
      },
    )
  })
}

#let render-tag-card(tag, count, href: none, tag-options: (:)) = {
  let target = if href == none { "/tags/" + str(tag) } else { href }
  html-guard(() => {
    html.a(
      class: "tag-card",
      href: target,
      style: tag-style-attr(tag, tag-options),
      {
        html.div(class: "tag-card-top", {
          html.div(class: "tag-card-name", tag)
          html.div(class: "tag-card-meta", str(count) + " 篇")
        })
        html.div(class: "tag-card-bottom", {
          html.span(
            class: "tag-card-icon",
            style: "mask-image:url(\"" + tag-icon-src(tag, tag-options) + "\");",
          )
          html.span(class: "tag-card-arrow")
        })
      },
    )
  })
}
