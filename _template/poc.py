#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC 模板 —— 复制到 <框架>-<版本>-<漏洞类型>-<CVE编号>/poc.py 后按需修改。

硬性约束:
  1. 零依赖: 只用 Python 标准库 (urllib, 不用 requests)。
  2. 非破坏性: 不写文件、不改配置、不执行命令; 证明执行只用 echo/id 类无副作用命令。
  3. 输出顺序固定: 目标 -> 注入点 -> 测试 payload -> 响应结果 -> 回调/证据 -> 结论 -> 原理。
  4. 退出码: 0=存在漏洞 1=不存在 2=参数或网络错误。
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

EXIT_VULN = 0
EXIT_SAFE = 1
EXIT_ERROR = 2

CVE_ID = "CVE-YYYY-NNNNN"
VULN_NAME = "产品 版本 漏洞类型"


def build_request(url):
    """TODO: 按具体漏洞构造请求。返回 (method, url, headers, body_bytes)。"""
    headers = {"Content-Type": "application/json",
               "User-Agent": "poc-" + CVE_ID.lower() + "/1.0"}
    payload = {"TODO": "payload"}
    return "POST", url, headers, json.dumps(payload).encode()


def verify(target, timeout):
    """TODO: 按具体漏洞判定。返回 (status, body_text, hit, evidence)。"""
    method, url, headers, body = build_request(target)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        status, text = resp.status, resp.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, text = exc.code, exc.read(2000).decode("utf-8", "replace")
    except Exception as exc:
        return None, str(exc), False, ""

    hit = False
    evidence = ""
    # TODO: 更换为真实判定, 例如特征串出现在响应中
    # if "MARKER" in text:
    #     hit, evidence = True, "响应中出现 MARKER"
    return status, text, hit, evidence


def main():
    ap = argparse.ArgumentParser(description=VULN_NAME + " (" + CVE_ID + ") 非破坏性验证")
    ap.add_argument("-u", "--url", required=True, help="目标地址")
    ap.add_argument("-t", "--timeout", type=float, default=8.0, help="请求超时秒数")
    ap.add_argument("--proxy", default=None, help="HTTP 代理")
    ap.add_argument("-k", "--insecure", action="store_true", help="跳过 TLS 校验")
    args = ap.parse_args()

    if args.proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy}))
        urllib.request.install_opener(opener)

    parsed = urlparse(args.url)
    if not parsed.hostname:
        print("[结论]    ERROR URL 无法解析")
        return EXIT_ERROR

    print("[目标]    %s" % args.url)
    print("[注入点]  TODO: 说明注入位置")
    print("[Payload] TODO: 贴出实际发送的 payload")
    print("[监听]    TODO: 如需回调, 说明监听地址")

    status, text, hit, evidence = verify(args.url, args.timeout)
    if status is None:
        print("[响应]    请求失败: %s" % text)
        print("[结论]    ERROR 目标不可达")
        return EXIT_ERROR

    print("[响应]    HTTP %s, body: %s" % (status, " ".join(text.split())[:200]))

    if hit:
        print("[证据]    %s" % evidence)
        print("[结论]    VULNERABLE - %s (%s)" % (VULN_NAME, CVE_ID))
        print("[原理]    TODO: 一两句话说明漏洞根因")
        return EXIT_VULN

    print("[结论]    NOT VULNERABLE - TODO: 说明未命中的依据")
    return EXIT_SAFE


if __name__ == "__main__":
    sys.exit(main())
