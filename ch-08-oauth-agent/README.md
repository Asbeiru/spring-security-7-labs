# 第（八）篇：OAuth 资源服务器与 Agent 工具门禁

对应《Spring Security 权威指南》第（八）篇 v2。Java 21、Spring Boot 4.1.1、Spring Security 7.1.1（由 Boot 管理）、Spring AI 2.0.2。

## 启动与测试

```powershell
mvn test
mvn spring-boot:run
```

`application.yml` 里的模型密钥是占位值。测试用 Mock 替换了 `JwtDecoder`，不会访问 `https://auth.zhouzhou.com`，也不会调用大模型。`POST /agent/chat` 才会真正请求模型。

## 这个工程包含什么

- 无状态 JWT 资源服务器，以及 `/.well-known/oauth-protected-resource`
- `@PreAuthorize` 工具门禁，和按参数绑定、一次性消费的人工审批
- 检索前把租户与密级写进过滤表达式

文章里没有给出、但容器启动需要的部分：

- `VaultAgentApplication`
- `DocumentAclService`：`PermissionEvaluator` 要调用它，默认没有任何共享授权
- `InMemoryDocumentStore`：按元数据过滤的内存文档存储，不做向量相似度

没有实现授权服务器、DPoP，也没有 RFC 8693 令牌交换。DPoP 在安全配置里保持注释，和文章一致。
