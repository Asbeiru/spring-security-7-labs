# 第（六）篇配套代码：授权新模型与对象级访问控制

对应[《Spring Security 权威指南（六）—— 授权新模型 AuthorizationManager 与细粒度访问控制》v4](../../../notes/zhihu/spring-security-guide/06-授权新模型AuthorizationManager与细粒度访问控制-v4.md)。这是独立 Maven 项目，使用 Java 21、Spring Boot 4.1.1 和 Spring Security 7.1.1。

## 启动

```powershell
$env:DEMO_PASSWORD = 'demo-only-123'
mvn test
mvn spring-boot:run
```

默认端口为 8080。用 HTTP Basic 访问三个文档：

```powershell
curl.exe -i -u alice:demo-only-123 http://localhost:8080/api/tenants/t1/documents/d1
curl.exe -i -u bob:demo-only-123 http://localhost:8080/api/tenants/t1/documents/d1
curl.exe -i -u carol:demo-only-123 http://localhost:8080/api/tenants/t2/documents/d3
curl.exe -i -u admin:demo-only-123 http://localhost:8080/api/admin/summary
```

第一、三、四个请求返回 `200`；Bob 读取 Alice 的文档返回 `403`。`TenantAuthorizationManager` 读取路径变量，提前检查租户成员资格；`DocumentService#read` 的 `@PreAuthorize` 独立检查成员资格，通过后才读取文档，`@PostAuthorize` 再核对文档的真实租户和所有者。因此，其他 Bean 经 Spring 代理调用 Service 时也必须满足这三项条件。管理接口同时受 Web 角色规则和 `@PreAuthorize` 保护。未匹配的请求由 `denyAll()` 拒绝。

`mvn test` 共执行 6 项测试。在随机端口验证匿名、跨租户、同租户越权、路径伪装、管理员规则和默认拒绝；直接调用容器中的 Service 代理，验证以下行为：

- alice 只有 `TENANT_t1`，即使是 d4 的所有者，也不能调用 `read("t2", "d4")` 读取 t2 的文档。
- alice 可以读取 t1/d1，carol 可以读取 t2/d3。
- alice 不能借 t1 路径读取实际属于 t2 的 d4，也不能读取同租户中属于 bob 的 d2。
- bob 不能读取 alice 的 d1，也不能执行管理员汇总。

直接方法调用被拒绝时抛出 `AuthorizationDeniedException`；经 HTTP 调用时再由异常翻译组件生成响应。这些检查要求调用经过 Spring 代理，`this.read(...)` 自调用不能作为授权边界。

项目中的用户和文档仅存于内存；真实系统需要由数据库查询、租户身份来源、权限变更和审计机制支撑。这里使用的授权模型只覆盖文章中的 RBAC 与基于租户、所有者属性的 ABAC 示例；ReBAC 和 ACL 留在文章中作选型比较。
