package com.zhouzhou.agent.security.config;

import org.springframework.aop.Advisor;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.method.AuthorizationInterceptorsOrder;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;

import com.zhouzhou.agent.approval.ApprovalService;
import com.zhouzhou.agent.approval.HumanApprovalAuthorizationManager;
import com.zhouzhou.agent.approval.RequiresHumanApproval;

@Configuration(proxyBeanMethods = false)
public class AgentMethodSecurityConfig {

    /**
     * HITL 拦截器：作用于所有 @RequiresHumanApproval 方法，排在 @PreAuthorize 之后执行
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor humanApprovalAdvisor(ApprovalService approvalService) {
        AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
                AnnotationMatchingPointcut.forMethodAnnotation(RequiresHumanApproval.class),
                new HumanApprovalAuthorizationManager(approvalService));
        interceptor.setOrder(AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder() + 1);
        return interceptor;
    }

    /**
     * 让 @PostFilter 中的 hasPermission(...) 使用自定义的文档权限判定
     */
    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler(PermissionEvaluator permissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        return handler;
    }
}
