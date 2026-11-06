# 第八篇 v2 修正版：OAuth 资源服务器与 Agent 方法授权

版本：Java 21、Spring Boot 4.1.1、Spring Security 7.1.1、Spring AI 2.0.2。

在本目录执行：

```powershell
mvn test
```

已缓存依赖时可执行 `mvn -o -B '-Dstyle.color=never' test`。本次 22 项测试通过，失败 0，错误 0。测试无需模型密钥，不连接外部授权服务器。

## 示例包含什么

- Bearer JWT 资源服务器、受众检查配置、RFC 9728 资源元数据与 401 发现地址。
- Spring AI 工具回调调用 Spring AOP 代理，执行 Scope、角色、租户账户与金额检查。
- 身份（签发方、租户、用户、客户端）、方法签名及参数绑定的人工审批。批准 15 分钟内有效，单进程原子消费一次。
- 审批方法自身要求 RISK_APPROVER；审批人必须是同签发方、同租户的另一位用户。
- RAG 查询过滤 + 独立 Bean 的 @PostFilter + PermissionEvaluator + 最终工具文本。

## 测试实际覆盖的边界

`VaultAgentSecurityTests` 用本地 RSA 密钥生成签名 JWT，替换授权服务器发现所需的 Decoder 配置，仍执行真正的 Nimbus 解码、签名和 iss/aud/时间校验。签发者与受众规则读取 application.yml，故配置与示例令牌不一致时测试也会失败。资源元数据测试同时检查默认本地地址与 HTTPS 公网地址，resource 由请求 URL 推导。工具测试由 `ToolCallbacks.from` 创建回调，执行 JSON 参数转换及 Spring 方法拦截。

`InMemoryDocumentStore` 只执行元数据条件，不计算语义相似度，不替代真实向量库的集成测试。部分方法授权测试直接安装已认证 JWT，以独立验证下游策略；这不表示未验签的令牌可经 HTTP 进入业务。

没有运行真实模型注入攻击、MCP 协议传输、DPoP 客户端证明或真实金融交易。没有审批页面、通知、持久化或任务自动恢复。`/test/identity` 仅存在于测试配置，不是生产端点。

## 正常启动的前提

应用配置中的 `https://auth.zhouzhou.com`、`https://api.zhouzhou.com` 是文章示例地址。使用 `mvn spring-boot:run` 接入真实环境前，需要换成自己的可信签发方与受众，配置兼容的模型服务及 `OPENAI_API_KEY`。调用 `/agent/chat` 会实际调用模型；本次回归测试没有这样做。

示例约定已验证 Access Token 包含非空的 `iss`、`sub`、`tenant_id`、`client_id`。RAG 额外要求整数 `security_clearance`（0 至 5）。权限来自 `scope`/`scp` 与由可信签发方管理的 `roles`；角色由自定义转换器加 `ROLE_`。这些业务声明不是仅靠 oauth2ResourceServer 就自动生成的。

固定账户目录：tenant-a 的来源为 VAULT-A，可调拨到 ACC-A001/ACC-A002；tenant-b 的来源为 VAULT-B，可调拨到 ACC-B001。本例不允许租户间调拨。真实系统应从授权账户目录读取资源；目录可变时，审批绑定还应涵盖确定的来源账户、目标账户和需要防止变化的资源信息。

## 人工审批

无有效批准时，转账工具抛出带工单号的 `HumanApprovalRequiredException`。另一个有 RISK_APPROVER 角色、同签发方和同租户的用户调用 `POST /admin/approvals/{ticketId}/approve`，随后原调用方重新发起工具调用。审批接口未注册成模型工具，客户端不能替模型提供一个“已审批”的布尔值。

`ApprovalService` 使用内存状态与同步方法示范原子消费。消费和业务方法体没有数据库事务，也没有跨实例一致性。业务执行失败不会恢复批准；请勿把 SIMULATED 结果当成真实交易成功。

## 文档权限

文档元数据为 `issuer`、`tenant_id`、`owner`、`confidentiality_level`。写入时由服务端补齐身份字段，并要求独立的 `SCOPE_rag:ingest`。共享关系由可信管理流程维护，示例未公开 ACL 写接口。

查询工具要求 `SCOPE_mcp:rag:query`。查询条件限制签发方、租户、密级；PostFilter 再确认这些边界与 owner/READ 授权。结果不足 topK 时不会用无权限文档补齐。

## 文件导航

- `src/main/java/com/zhouzhou/agent/security/config/`：过滤链、权限转换、方法授权 Advisor。
- `src/main/java/com/zhouzhou/agent/security/`：可信身份与账户归属。
- `src/main/java/com/zhouzhou/agent/approval/`：工单、审批管理器与审批接口。
- `src/main/java/com/zhouzhou/agent/tools/`：资产和知识库工具。
- `src/main/java/com/zhouzhou/agent/rag/`：检索、后置过滤与 ACL。
- `src/test/java/com/zhouzhou/agent/`：22 项回归测试。

本目录为文章 v2 修正版的配套代码。
