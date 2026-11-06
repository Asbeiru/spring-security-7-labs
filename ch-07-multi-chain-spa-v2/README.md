# 第（七）篇 v2：多安全过滤链与 SPA

对应《Spring Security 权威指南（七）—— 生产级多安全过滤链与 SPA 攻防实战》07-v2。本工程独立于既有 `ch-07-multi-chain-spa`，使用 Java 21、Spring Boot 4.1.1、Spring Security 7.1.1。旧工程和旧文章均保留。

## 启动与测试

先确保 `java -version` 为 JDK 21 或更新版本，在本目录运行：

```powershell
$env:DEMO_PASSWORD = 'demo-only-123'
mvn test
mvn spring-boot:run
```

监听 `127.0.0.1:8080`。`admin` 有 `ROLE_ADMIN`；`reader` 仅有 `ROLE_USER`，两者都使用 `DEMO_PASSWORD` 中的演示密码。密码必须显式提供；测试使用独立测试属性，不读取外部密码。

前端是供 SPA 导入的 TypeScript 模块，不包含页面或开发服务器。使用 Node.js 24 的原生类型擦除运行测试，无需 npm 安装：

```powershell
node --experimental-strip-types --test frontend/api.test.mjs
```

前端用替代 fetch 验证调用顺序，真实 Cookie 与 Session 由 Java HTTP 集成测试覆盖。前端成功的认证调用应走同一个实例的 `login()`、`logout()`，不能绕过它们只调用原始 api 后忘记清缓存。

## 端点

| 方法与路径 | 行为 |
|---|---|
| GET、HEAD `/api/v1/articles` | 公开链；不恢复后台身份 |
| POST `/api/v1/articles` | 故意保留写映射，验证公开链先返回 JSON 403，Controller 不执行 |
| GET `/api/v1/auth/csrf` | Session 中保存底层 Token，通过默认 XOR 处理器返回遮蔽后的值 |
| POST `/api/v1/admin/session` | 先 CSRF，再限流，再表单认证；成功 204，凭据失败 JSON 401 |
| GET `/api/v1/admin/session` | 查询当前登录身份，匿名 401 |
| POST `/api/v1/admin/articles` | 需要 ADMIN 与有效 Token，成功后内存计数加一，返回 204 |
| GET `/api/v1/admin/articles/count` | ADMIN 查询成功写入次数 |
| POST `/api/v1/admin/logout` | 有效 Token 退出，成功 204 |

## 登录与发文

登录前先取得 Token；登录成功会让旧 Token 失效，因此发文前重新获取。以下 PowerShell 示例复用同一份 Cookie 容器：

```powershell
$base = 'http://127.0.0.1:8080'
$browser = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$before = Invoke-RestMethod "$base/api/v1/auth/csrf" -WebSession $browser
Invoke-WebRequest "$base/api/v1/admin/session" -WebSession $browser -Method Post `
    -Headers @{ 'X-CSRF-TOKEN' = $before.token } `
    -ContentType 'application/x-www-form-urlencoded' `
    -Body @{ username = 'admin'; password = $env:DEMO_PASSWORD }
$after = Invoke-RestMethod "$base/api/v1/auth/csrf" -WebSession $browser
Invoke-WebRequest "$base/api/v1/admin/articles" -WebSession $browser -Method Post `
    -Headers @{ 'X-CSRF-TOKEN' = $after.token }
Invoke-WebRequest "$base/api/v1/admin/logout" -WebSession $browser -Method Post `
    -Headers @{ 'X-CSRF-TOKEN' = $after.token }
```

## 计数器与代理

默认 `demo.login-counter=memory` 不连接 Redis。该实现只用于单进程演示；它保留 IP 键直到同 IP 再次访问时更新，未实现主动清扫，不能作为生产内存限流服务使用。

切换到已有本地 Redis（不自动下载或启动服务）：

```powershell
mvn spring-boot:run '-Dspring-boot.run.arguments=--demo.login-counter=redis --spring.data.redis.host=127.0.0.1 --spring.data.redis.port=6379'
```

Redis 脚本原子执行 INCR，并且只在计数为 1 时设置 900 秒 TTL；这是从首次请求开始的固定过期窗口。默认测试没有连接真实 Redis，也没有执行分布式、故障切换和性能测试。

按 IP 累计所有通过 CSRF 的登录尝试，包括成功请求。计数大于 15 返回 JSON 429；计数器异常或 null 返回 JSON 503，均不进入密码认证。无效 CSRF 请求先返回 403，不计数。

默认不信任任何代理头，`server.forward-headers-strategy=none` 保留直接连接地址。仅在确有可信反向代理且后端访问路径受到限制时，配置 `demo.trusted-proxy-cidrs`，例如 `10.20.0.0/16`。代理必须覆盖 `X-Site-Client-IP`，不能透传客户端提供的同名值；多级代理还需逐跳配置真实地址的信任关系。

## 回归范围

- `FilterChainOrderTest`：启动拒绝默认全匹配链在前；显式 `/**` 路径可能遮蔽后链；默认单链 GET 不必访问 Session。
- `MultiChainApplicationTest`：真实 HTTP 的公开链、Session ID 更换、CSRF 生命周期、XOR 表示、401/403、限流顺序与第 16 次 JSON 429。
- `InMemoryLoginAttemptCounterTest`：首次请求起计时、TTL 不随尝试延长、地址隔离。
- `LoginThrottleTest`：429/503 立即停止、null 不被误报为超额、context path 下精确匹配。
- `ClientAddressTest`：不可信来源不能自选 Header 身份、有效字面量解析、非法值回退、IPv6 表示归一。
- `frontend/api.test.mjs`：方法大小写、单次并发握手、登录/退出清缓存、失败不重放写入、握手失败恢复。

这是安全组件行为实验。发文只增加内存计数，没有数据库、真实业务方法授权、完整部署或浏览器页面。
