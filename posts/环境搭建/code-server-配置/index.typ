#import "../../../config.typ": *

#show: template-post.with(
  title: "Code-server 配置",
  description: "在 Windows 上使用 WSL ，在 WSL 上使用 VSCode ，在 VSCode 上使用 Code-server。",
  tags: ("Windows", "WSL", "VSCode", "Code-server",),
  category: "环境搭建",
  date: datetime(year: 2022, month: 3, day: 30)
)

#quote[
Code-server 感觉不错，免去我远程桌面的麻烦。
]

== 安装

+ 下载 Code-server
#link("https://github.com/coder/code-server/releases/tag/v4.2.0")
+ 解压 `tar -xvzf code-server.tar.gz`
+ cd 进解压后的目录，`./code-server /home` `/home` 可以替换成你想要的目录(这步不要在 VSCode 的终端执行)

== 配置

找到 ~/.config/code-server/config.yaml ， `bind-addr` 项可以改你想要的端口，如 `127.0.0.1：8080` ， `password` 项可以改密码。
然后用 Nginx 代理出去就能在局域网上访问了。

#quote[
_ref:_
]
#link("https://www.cnblogs.com/billyme/p/13769847.html")
#link("https://blog.csdn.net/mijichui2153/article/details/18880283")
