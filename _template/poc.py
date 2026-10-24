#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PoC 模板 —— 复制到 <框架>-<版本>-<漏洞类型>-<CVE编号>/poc.py 后按需修改。

编写原则:
  1. 只做非破坏性验证: 回显特征串 / 延时对比 / 唯一标记, 不写文件、不留后门、不改配置。
  2. 单文件可运行, 只依赖 requests。
  3. 退出码约定: 0=漏洞存在  1=不存在  2=参数或网络错误。
"""
import argparse
import sys
import time

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[!] 缺少依赖, 请先执行: pip install -r requirements.txt")

EXIT_VULN = 0
EXIT_SAFE = 1
EXIT_ERROR = 2

MARKER = "poc-verify-7f3a"


def build_payload(url):
    """构造验证请求. TODO: 按具体漏洞修改. 返回 (method, target_url, kwargs)."""
    target = url.rstrip("/") + "/TODO-endpoint"
    headers = {"User-Agent": "poc-check/1.0"}
    data = {"param": MARKER}
    return "GET", target, {"headers": headers, "params": data}


def check(url, timeout, proxy, verify):
    method, target, kwargs = build_payload(url)
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        started = time.time()
        resp = requests.request(method, target, timeout=timeout, proxies=proxies,
                                verify=verify, allow_redirects=False, **kwargs)
        elapsed = time.time() - started
    except requests.RequestException as exc:
        print("[!] 请求失败: %s" % exc)
        return EXIT_ERROR

    body = resp.text if resp.text else ""

    # TODO: 按漏洞特征判定. 示例: 延时型
    # if elapsed >= 4 and MARKER in body:
    #     return EXIT_VULN

    print("[*] %s %s -> HTTP %s (%.2fs, %d bytes)" %
          (method, target, resp.status_code, elapsed, len(body)))

    if MARKER in body:
        print("[+] 目标回显了验证标记, 疑似存在漏洞")
        return EXIT_VULN

    print("[-] 未命中漏洞特征")
    return EXIT_SAFE


def main():
    parser = argparse.ArgumentParser(
        description="PoC 验证脚本模板 (仅限授权测试)")
    parser.add_argument("-u", "--url", required=True, help="目标地址, 如 http://1.2.3.4:8080")
    parser.add_argument("-t", "--timeout", type=float, default=10.0, help="请求超时秒数, 默认 10")
    parser.add_argument("--proxy", default=None, help="HTTP 代理, 如 http://127.0.0.1:8080")
    parser.add_argument("-k", "--insecure", action="store_true", help="跳过 TLS 证书校验")
    args = parser.parse_args()

    verify = not args.insecure
    code = check(args.url.rstrip("/"), args.timeout, args.proxy, verify)

    if code == EXIT_VULN:
        print("[RESULT] VULNERABLE")
    elif code == EXIT_SAFE:
        print("[RESULT] NOT VULNERABLE")
    else:
        print("[RESULT] ERROR")
    return code


if __name__ == "__main__":
    sys.exit(main())
