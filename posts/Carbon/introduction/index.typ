#import "../../../config.typ": *
#import "@preview/lilaq:0.5.0" as lq

#show: template-post.with(
  title: "Carbon Typst Blog 介绍",
  description: "本文主要介绍 Carbon Typst Blog 的基本功能和配置方式。",
  tags: ("博客搭建",),
  category: "博客的构建和调整",
  date: datetime(year: 2026, month: 3, day: 17)
)

= 简要介绍

Carbon Typst Blog 是一个以 Carbon 设计系统为基础，基于 Typst 编写的博客模板，其构建脚本通过 Node.js 环境运行。

你可以通过更改 Typst 文件管理博客和额外生成的页面。以下是模板自带的页面：

#table(
  columns: 3,
  table.header(
    [Typst 文件], [生成的页面路径], [页面内容],
  ),
  [`pages/index.typ`], [`/`], [首页文章列表\*],
  [`pages/about/index.typ`], [`/about/`], [关于页面],
  [`pages/archive/index.typ`], [`/archive/`], [文章归档],
  [`pages/tags/index.typ`], [`/tags/`], [标签总览],
  [`pages/tags/[tag]/index.typ`], [`/tags/[tag-slug]/`], [标签详情\*],
  [`pages/categories/index.typ`], [`/categories/`], [分类总览],
  [`pages/categories/[category]/index.typ`], [`/categories/[category-slug]/`], [分类详情\*],
  [`posts/[slug]/index.typ`], [`/posts/[slug]/`], [文章详情页],
)

\* 注：文章展示页面可能会分页，其页面路径会通过在默认的页面路径后面追加 `/page/[页码]` 得到。

上面的 `[tag]` 和 `[category]` 行使的功能和 Astro 类似。构建脚本会自行填写所有可能的标签和分类，并且通过命令行参数传递给 Typst 页面。有关命令行参数的行为，请参考下方「构建指令说明」。

*构造脚本只会编译文件名为 `index.typ` 的 Typst 文件，并生成对应路径的页面，其他 Typst 文件会自动忽略。*尽管如此，你依然可以使用 `import` 语法在 Typst 文件内部引用其他 Typst 文件。

最后，你可以调整如下设置文件，从而影响博客的整体效果：

- `config.typ`：
  全站配置入口，通常用来统一定义导航链接、页脚信息、模板默认值与主题相关参数。有关 `config.typ` 可以配置的全部内容，可以参考 #link("/posts/config-typ/")[配置文件说明]。

- `site.config.json`：
  配置站点标题、站点地址、描述和语言，主要影响 RSS 输出内容。

- `assets/custom.css`：
  样式覆盖入口，会在核心样式之后加载，适合做个性化视觉调整。

- `assets/custom.js`（可选）：
  自定义前端脚本入口，适合放一些非核心交互逻辑。仓库默认可能没有这个文件，需要时可以自行创建，并在 `config.typ` 的模板参数里通过 `custom-script` 引入。

= 搭建步骤

为了在本地搭建 Carbon Typst Blog，你需要执行如下步骤：

1. 确认本地存在较新的 Node.js 和 Typst 运行环境；
2. 将模板仓库克隆到本地；
3. 进入仓库根目录（也就是包含 `package.json` 的目录），然后运行构建命令。常用命令如下：
  - `npm run build` ：执行常规构建，输出目录为 `_site/`；
  - `npm run build:fast` ：使用 `--jobs 4` 并发构建；
  - `npm run build:preview` ：输出到 `_site-preview/`，方便预览效果；
  - `npm run build:preview_fast` ：使用 `--jobs 4` 并发构建并输出到 `_site-preview/`。
4. 在本地启动 Live Server 进行预览，或者将生成的站点页面部署到云端。

目前构建流程会从 source 全量写入 staging 后再原子替换输出目录，不再复用旧 `_site` 产物，因此一般情况下不需要额外的“强制刷新”开关。

GitHub Actions 自动部署配置正在编写中，后续会补充完整的 CI/CD 示例（包括自动构建与发布流程）。

= 构建指令说明

除了 `npm run build` 命令之外，你还可以使用下面这个入口命令进行构建：

```
node lib/node/build-html.mjs
```

这个命令后面可以接一些可选参数。以下是所有可用的参数列表：

#table(
  columns: 2,
  table.header(
    [参数], [作用],
  ),
  [`-o` 或 `--out <目录>`], [指定输出目录；不写时默认输出到 `_site`],
  [`-j` 或 `--jobs <数量>`], [指定 Typst 编译并发数],
  [`-c` 或 `--config <路径>`], [指定配置文件路径；不写时默认使用 `config.typ`],
  [`--cache-root <目录>`], [指定缓存目录；不写时默认使用 `.typ-blog-cache`],
  [`-h` 或 `--help`], [打印完整帮助信息]
)
