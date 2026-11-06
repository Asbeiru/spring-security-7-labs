# 第（五）篇配套代码：会话治理与安全上下文

这份独立 Maven 项目对应[《Spring Security 权威指南（五）—— 会话治理、安全上下文与现代无密码认证》对照版](../../../notes/zhihu/spring-security-guide/05-会话治理安全上下文与现代无密码认证-对照版.md)第三节。`SessionDemoApplication.java` 与文章中的完整 Java 示例一致，采用 Spring Boot 4.1.1、Spring Security 7.1.1 和 Java 21。

## 运行

在本目录打开 PowerShell，使用 JDK 21 或更高版本：

```powershell
$env:DEMO_PASSWORD = 'demo-only-123'
mvn test
mvn spring-boot:run
```

默认监听 `http://localhost:8080`。打开 `/login`，用 `zhouzhou` 和设置的密码登录，然后访问 `/me`。在另一个不共享 Cookie 的浏览器配置文件中登录相同账号，第二次登录会被拒绝；首个浏览器仍可访问 `/me`。要重新测试，请在首个浏览器提交 `/logout`，或重启应用。

测试在随机端口发起真实 HTTP 请求，检查登录前访问控制、CSRF、登录时 `JSESSIONID` 轮换、第二处登录被拒绝、首个会话继续有效，以及登出后第二处可以登录。测试使用独立 Cookie 容器，不需要真实浏览器或外部服务。

本项目演示文章中的**有状态表单登录**。文章其余部分讨论的 Remember-Me、Bearer Token、一次性令牌与 Passkeys 是机制比较和配置边界，不在这份单入口示例中同时启用。内存用户和单机 `SessionRegistry` 仅供教学；生产环境需要持久化用户与跨节点会话方案。
