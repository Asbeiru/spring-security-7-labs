# 第（四）篇配套代码：短信验证码登录

这份独立 Maven 项目对应[《Spring Security 权威指南（四）—— 认证架构与核心组件庖丁解牛》对照版](../../../notes/zhihu/spring-security-guide/04-认证架构与核心组件庖丁解牛-对照版.md)第七节。`SmsLoginApplication.java` 与文章里的 Java 代码一致，可以边读边在断点中追踪 `SmsConverter → SmsToken → ProviderManager → SmsProvider → AuthenticationFilter → SecurityContextRepository`。

## 版本与启动

- Java 21 或更高版本，Maven 3.6.3 或更高版本。
- Spring Boot `4.1.1`，其依赖解析到 Spring Security `7.1.1`；文章的机制还对照了本地 `7.2.0-SNAPSHOT` 源码。
- 运行前设置 `DEMO_SMS_CODE`。验证码只在启动时放入内存，有效期三分钟，成功后只能使用一次；超时后重新启动应用。

在本目录打开 PowerShell：

```powershell
$env:DEMO_SMS_CODE = '654321'
mvn test
mvn spring-boot:run
```

也可以用 `mvn package` 打包，再运行 `java -jar target/sms-login-demo-0.0.1.jar`。默认监听 `http://localhost:8080`。若当前命令行使用的 Java 版本低于 21，请先将 `JAVA_HOME` 指向 JDK 21 或更高版本，并把其 `bin` 目录放在 `PATH` 首位。测试会自行启动随机端口，不占用 8080。

## 手动走一遍登录通道

在另一个 PowerShell 窗口执行下面的请求。同一个 `WebRequestSession` 会保存 `JSESSIONID`：

```powershell
$base = 'http://localhost:8080'
$session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$csrf = Invoke-RestMethod "$base/csrf" -WebSession $session
$headers = @{}
$headers[$csrf.headerName] = $csrf.token

$login = Invoke-WebRequest "$base/login/sms" -Method Post `
    -WebSession $session -Headers $headers `
    -ContentType 'application/x-www-form-urlencoded' `
    -Body @{ phone = '13800138000'; code = $env:DEMO_SMS_CODE }
$login.StatusCode # 204

Invoke-RestMethod "$base/me" -WebSession $session
# name=13800138000，authenticated=true
```

登录会清除旧 CSRF Token。若要再次发起 POST，须先重新请求 `/csrf` 并回传新 Token；已经消费的验证码仍会被拒绝。`mvn test` 自动核查匿名访问、CSRF 校验、错误码、登录后的 Session 恢复、旧 Token 失效及验证码单次消费；另有单元测试展示 `ProviderManager` 轮询、父级兜底、凭据擦除，以及 DAO Provider 的密码哈希迁移。匿名请求缺少 CSRF Token 时，本例的认证入口返回 `401`；登录后使用旧 Token 则返回 `403`。

这是认证架构教学样例：手机号、用户、验证码都在内存中；没有短信签发、发送、限流、审计、共享存储，也没有并发会话控制。接入真实业务时，这些能力要由相应服务和会话策略补齐。
