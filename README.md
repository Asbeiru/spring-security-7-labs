# Spring Security 7 配套工程

《Spring Security 权威指南》的可运行示例。Java 21，Spring Boot 4.1.1。每个目录是独立的 Maven 工程，进入目录后执行 `mvn test`。

| 目录 | 内容 |
|---|---|
| `ch-04-sms-login` | 认证架构与短信登录 |
| `ch-05-session-context` | 会话与安全上下文 |
| `ch-06-authorization` | 授权与方法安全 |
| `ch-07-multi-chain-spa` | 多安全过滤链与 SPA |
| `ch-07-multi-chain-spa-v2` | 第 07 篇配套的修订版 |
| `ch-08-oauth-agent` | OAuth 资源服务器、工具门禁与人工审批 |
| `bonus-agent-security` | Agent 工具授权加餐 |

演示口令写在各章说明里，只用于本地示例。`ch-08-oauth-agent` 的模型密钥是占位值，测试不会访问授权服务器或大模型。
