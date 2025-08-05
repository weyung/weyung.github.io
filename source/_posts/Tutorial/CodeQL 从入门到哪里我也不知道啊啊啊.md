---
title: CodeQL 从入门到哪里我也不知道啊啊啊
date: 2025-07-31 15:18:00
tags: [静态分析]
categories: 学习
---

怎么全是报错啊啊啊啊啊啊
<!--more-->

## What is CodeQL?

CodeQL 是由 GitHub 开发的一款语义代码分析引擎，它允许开发者和安全研究人员通过编写查询来发现代码中的漏洞和安全问题。与传统静态分析工具不同，CodeQL 将代码视为数据，通过查询代码中的数据关系来发现潜在问题。

跟 SQL 长挺像

需要少许数据库的基础，至少得能看懂简单的查询语句

## 做个小测试

假设有以下 Python 代码：

```python
if error: pass
```

很明显，这个 `if` 语句是冗余的，因为它啥都没干，有没有都一样。
那么我们可以用 CodeQL 来查找这种冗余的 `if` 语句。
使用以下 CodeQL 查询：

```ql
import python

from If ifstmt, Stmt pass
where pass = ifstmt.getStmt(0) and
  pass instanceof Pass
select ifstmt, "This 'if' statement is redundant."
```

那这个 QL 是什么意思呢

`import python` 是导入 Python 语言的 CodeQL 库，里面定义了如何处理 Python 代码，正如你平时的编程一样，一般情况下，库文件如何通过底层代码实现是无需理会的。
`from If ifstmt, Stmt pass` 是在查询中定义了两个变量：`ifstmt` 和 `pass`，`If` 和 `Stmt` 分别是对应的 CodeQL 类型。`If` 代表一个 if 语句，而 `Stmt` 代表一个通用的语句。
`where pass = ifstmt.getStmt(0) and pass instanceof Pass` 是查询的条件部分，包含两个条件：

1. `pass = ifstmt.getStmt(0)`：表示 `ifstmt` 的第一个语句是 `pass`。
2. `pass instanceof Pass`：表示 `pass` 是一个 `Pass` 语句。

`select ifstmt, "This 'if' statement is redundant."` 是查询的结果部分，表示如果满足上述条件，则返回 `ifstmt` 和一条消息，如此就可以找到所有冗余的 if 语句。

## 更深层次的查询

// TODO

## 参考

<https://codeql.github.com/docs/codeql-language-guides/basic-query-for-python-code/>
