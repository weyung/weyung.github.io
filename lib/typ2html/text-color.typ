#import "html-guard.typ": html-guard

#let template-text-color(body) = {
  show text: it => context {
    let c = text.fill
    if type(c) == color and c != black {
      html-guard(
        () => html.elem("span", attrs: (style: "color: " + c.to-hex()), it),
        fallback: () => it,
      )
    } else {
      it
    }
  }
  body
}
