# 第（七）篇配套代码：多安全过滤链与 SPA CSRF

对应[《Spring Security 权威指南（七）—— 生产级多安全过滤链与 SPA 攻防实战》对照版](../../../notes/zhihu/spring-security-guide/07-生产级多安全过滤链与SPA攻防实战-对照版.md)。这是 Java 21、Spring Boot 4.1.1、Spring Security 7.1.1 的独立 Maven 项目，提炼了 `decodingProjects` 的双链结构，不依赖 Redis 或数据库即可运行。

## 运行

先将 `JAVA_HOME` 指向 JDK 21 或更新版本；本机系统默认的 Java 8 无法运行 Spring Boot 4。下例使用本机已安装的 JDK 25：

```powershell
$env:JAVA_HOME = 'D:\soft\datagrip\DataGrip 2026.2.6\jbr'
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
$env:DEMO_PASSWORD = 'demo-only-123'
mvn test
mvn spring-boot:run
```

默认监听 `http://localhost:8080`。公开接口 `GET /api/v1/articles` 返回 `200`，不会创建安全会话。管理入口通过 `GET /api/v1/auth/csrf` 取得 CSRF Token，再带 `X-CSRF-TOKEN` 和同一浏览器的 `JSESSIONID` 提交 `POST /api/v1/admin/session` 表单。登录成功返回 `204`；此时旧 Token 已失效，需再次获取后才能提交 `POST /api/v1/admin/items`。登出接口为 `POST /api/v1/admin/logout`。

`mvn test` 使用独立 Cookie 容器和真实 HTTP 请求，验证：公开链不恢复管理身份、公开路径上的 POST 被拒绝、管理登录需要 CSRF、登录后旧 Token 失效、写入使用新 Token、登出清理身份与 Token。另有 `DemoLoginThrottleTest` 验证同一地址的第 16 次请求返回 `429`。

演示版限流器是单进程内存计数，只用于让项目自包含；它不会主动清扫长期不再访问的 IP 键，也没有跨节点一致性。真实项目的 [`LoginThrottle.java`](../../../../decodingProjects/backend/src/main/java/com/zhouzhou/site/LoginThrottle.java) 使用 Redis Lua 原子递增及 15 分钟过期：计数超过 15 或脚本返回 `null` 时给 `429`，执行抛异常时给 `503`。两者不能等同。真实项目的前端 CSRF 生命周期见 [`shared/api.ts`](../../../../decodingProjects/frontend/shared/api.ts) 和 [`admin/src/session.ts`](../../../../decodingProjects/frontend/apps/admin/src/session.ts)。
