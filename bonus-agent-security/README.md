# Bonus Agent Security：复现实验

本工程只测试授权边界，不启动服务器，不需要 API key、Docker 或真实业务数据。

环境（实际执行 2026-10-25，America/Los_Angeles）：
- Temurin 21.0.12.1+1-LTS，Maven 3.6.3
- Spring Boot 4.1.1；解析的 Spring Security core/config/web/crypto 均 7.1.1
- Java 编译目标 21；使用已有 Maven 缓存（本机 localRepository 为 D:/repository）

从本目录运行：

```powershell
mvn -o test
mvn -o dependency:tree '-Dincludes=org.springframework.security:*,org.springframework.boot:*'
```

缓存不全时去掉 `-o`，由自己的 Maven 仓库配置下载；本文未安装/升级全工程依赖。

本轮复审实际结果：22 tests, 0 failures, 0 errors, 0 skipped。原始结果见 [test-results-review2.log](test-results-review2.log)，依赖见 [dependency-versions.log](dependency-versions.log)。初版21项记录保留在 [test-results.log](test-results.log)。

复审修正：任何携带审批票据的请求都先做绑定匹配和消费，不再只在新金额仍高于100时检查票据。新增回归测试覆盖携票据从200降到50、换成读取动作、已消费票据的降额重放，以及不带票据的普通小额请求仍按独立权限执行。

- `AgentSecurityTest`：20 项，包括许可/拒绝、副作用、跨租户、类型与金额、委托范围与父链、过期/撤销、反射入口、审批绑定/资格/过期/拒绝/重放、虚拟线程与池线程隔离、并发消费。
- `ControlSecurityTest`：2 项，通过真实 FilterChainProxy 选择过滤链，模拟 Servlet 请求与 Session 内可信认证；不测试登录、JWT/MCP 网络握手；GET 只用于把授权拒绝与 CSRF 拒绝分开，不提供实际写接口。

代码边界：
- `Grant`、`DelegationAuthenticationToken`、`Registry`、`Gateway`、`Approvals` 均为本文自定义。`ToolPolicy` 实现真实 `AuthorizationManager<Request>`。
- `seed` 只用于可信夹具，`delegate/revoke` 假设受信任内部服务调用；没有对外签发端点，也没有实现当前 delegator 身份校验。不要把它们直接注册为工具。
- 测试根委托故意把 other 租户的 brief-b 加入候选资源集合，确保跨租户案例失败于服务端租户比对，而不只是缺少资源 ID。图中展示正常业务范围。
- 根委托seed未核实alice实时权限，task只保证父子任务ID一致，未检查周报完成阶段；审批账户的“非Agent token + ROLE_APPROVER”也不是现实人类身份的正向证明。
- 固定执行目录仅 documents.read / expenses.submit；没有任意反射分发。反射测试只调用公开的 Gateway.execute。
- 读取返回状态，报销只递增内存计数，不访问财务系统；这验证门禁之前/之后的位置，不是数据库或真实支付集成测试。
- 委托/撤销/工单仅内存存储；没有跨进程持久化、多实例 CAS、业务事务、幂等消息或崩溃恢复。Gateway 同步锁只串行化同实例执行，不锁住 Registry 的并发撤销。
- 默认 ThreadLocal 策略；包装器捕获引用，夹具每任务建立独立上下文，不能把它理解成深拷贝。40 个身份任务分别交给虚拟线程与普通池；异常后复用池线程检查清理。
- 无真实 LLM、约束查询/TPE、预算规划器、企业审批目录、业务审计、跨域凭证实现。这些边界均在正文注明。

本次没有提交、推送或启动服务。不要提交 Maven target/。
