---
title: HackTheBox 笔记
date: 2024-05-17 20:12:00
tags: [Web, 渗透]
categories: 渗透
---

不得不找饭吃了。

<!--more-->

## 新手村

四道基础题，基本就是 nmap 扫。
主要记住一些参数，比如 `-p-` 扫描所有端口，`--min-rate <num>` 设置扫描速率，`-n` 不解析域名，`-sS` SYN 扫描，`-Pn` 不 ping 主机，`--open` 只显示开放端口，`--stats-every <num>` 每扫描多少个端口显示一次统计信息，`-vv` 详细输出。

## Two Million

扫出来两个端口，一个是 80，一个是 22。

访问 80 端口，301 到 2million.htb，改 `etc/host` 加一行 `10.10.11.221    2million.htb`，再访问，发现是个登录页面。
根据提示找到 `inviteapi.min.js`，内容如下：

```javascript
eval(
  function (p, a, c, k, e, d) {
    e = function (c) {
      return c.toString(36)
    };
    if (!''.replace(/^/, String)) {
      while (c--) {
        d[c.toString(a)] = k[c] ||
        c.toString(a)
      }
      k = [
        function (e) {
          return d[e]
        }
      ];
      e = function () {
        return '\\w+'
      };
      c = 1
    };
    while (c--) {
      if (k[c]) {
        p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c])
      }
    }
    return p
  }(
    '1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',
    24,
    24,
    'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),
    0,
    {
    }
  )
)
```

打开 [de4js](https://lelinhtinh.github.io/de4js/) 去混淆得到：

```javascript
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}
```

执行

```bash
curl  http://2million.htb/api/v1/invite/how/to/generate -X POST
```

得到

```json
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```

直接 CyberChef 解 ROT13 得到 In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate。
好吧，改个 PATH，再 POST 一下，得到

```json
{"0":200,"success":1,"data":{"code":"QUtZOEYtMENKMzMtSEE5OVEtS1VHTzQ=","format":"encoded"}}
```

解码得到 `AKY8F-0CJ33-HA99Q-KUGO4`，POST 到 `/api/v1/invite/verify`，得到

```json
{"0":200,"success":1,"data":{"verified":true}}
```

注册登录后，顺着提示点击 Connection Pack，下载链接为 `/api/v1/user/vpn/generate`。
访问 `/api/v1`，得到

```json
{"0":200,"success":1,"data":{"user":{"id":1,"username":"admin","email":"
