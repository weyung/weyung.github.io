#import "../../config.typ": *

#show: template-page.with(
  title: "友链",
  description: "友链页面",
)

#render-page-breadcrumb(items: (("/", "首页"),))

// 定义一组好看的浅色卡片背景色
#let card-colors = (
  "#f0fdfa", // 浅青
  "#fff1f2", // 浅粉
  "#f0f9ff", // 浅蓝
  "#fefce8", // 浅黄
  "#f5f3ff", // 浅紫
  "#f7fee7", // 浅绿
)

// 提取公共的卡片网格渲染函数
#let render-friend-group(friend-list) = {
  html.elem("div", attrs: (
    class: "posts-grid",
    style: "display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem;"
  ), {
    for (i, friend) in friend-list.enumerate() {
      let bg-color = card-colors.at(calc.rem(i, card-colors.len()))
      html.elem("div", attrs: (
        class: "post-card",
        "data-post-url": friend.url, 
        "data-post-target": "_blank",
        style: "background-color: " + bg-color + ";",
      ), {
        html.div(class: "post-title", {
          html.a(class: "post-card-link", href: friend.url, target: "_blank", friend.name)
        })
        html.div(class: "post-description", {
          friend.desc
        })
      })
    }
  })
}

= 友链

#note(title: "欢迎来交换友链ヾ(≧▽≦*)o")[
  #figure()[
    ```yaml
    - name: weyung
      link: https://blog.weyung.cc/
      avatar: https://blog.weyung.cc/images/avatar.png
      descr: 写一些和我一样菜也能看懂的文章
    ```
  ]
]

== DaLaos

#let dalaos = (
  (name: "GZTime", url: "https://blog.gztime.cc/", desc: "Walking on the Time Axis."),
  (name: "小傅Fox", url: "https://xfox.me/", desc: "一个博客不写技术的 dalao"),
  (name: "Darkyzhou", url: "https://darkyzhou.net/", desc: "MC 爱好者"),
  (name: "jiahonzheng", url: "https://blog.jiahonzheng.com/", desc: "请叫他 ++"),
  (name: "春哥", url: "https://www.zhihu.com/people/ZM_________J/", desc: "一人攻沙虐全场"),
)

#render-friend-group(dalaos)

== 朋友们

#let friends = (
  (name: "Hanmur", url: "https://hanmur.cn/", desc: "一位帅气且有趣的学长"),
  (name: "yescallop", url: "https://yescallop.cn/", desc: "Rust 水平相当高"),
  (name: "FluoriteFire", url: "https://fluoritefire.github.io/", desc: "Walking to a new world"),
  (name: "Tel", url: "https://l1nyz-tel.cc/", desc: "where are you"),
  (name: "a39", url: "http://www.asuka39.top/", desc: "歩いても、歩いても"),
  (name: "Elapsedf", url: "https://elapsedf.cn/", desc: "Think what you want"),
  (name: "Pazuris", url: "https://blog.pazuris.cn/", desc: "Fear neither hardship nor darkness"),
  (name: "yring", url: "https://yring-me.com/", desc: "冥冥之中 自有天意"),
  (name: "LilRan", url: "https://blog.xinshi.fun/", desc: "今日启程 无畏向前"),
  (name: "Lst4r", url: "https://lst4r-max.github.io/", desc: "小铁大客户"),
  (name: "夏槿", url: "https://uniya.work/", desc: "的小屋"),
  (name: "lbyxiaoliz", url: "https://blog.vh.gs", desc: "喵喵喵喵喵"),
)

#render-friend-group(friends)