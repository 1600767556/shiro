package com.bjpowernode.shiro.config;


import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import com.bjpowernode.shiro.realm.MyRealm;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

//标记当前类是一个Spring的配置类用于模拟Spring的配置文件
@Configuration
public class ShiroConfig {

    /**
     * 配置一个SecurityManager 安全管理器
     *
     */
    @Bean
    public SecurityManager securityManager(Realm myRealm){
        DefaultWebSecurityManager defaultWebSecurityManager=new DefaultWebSecurityManager();
        defaultWebSecurityManager.setRealm(myRealm);
        return defaultWebSecurityManager;
    }
    //配置一个自定义的Realm的bean，最终将使用这个bean返回的对象来完成我们的认证和授权
    @Bean
    public MyRealm myRealm(){
        MyRealm myRealm=new MyRealm();
        return myRealm;
    }
    //配置一个Shiro的过滤器bean，这个bean将配置Shiro相关的一个规则的拦截
    //例如什么样的请求可以访问什么样的请求不可以访问等等
    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager){
        //创建过滤器配置Bean
        ShiroFilterFactoryBean shiroFilterFactoryBean=new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        shiroFilterFactoryBean.setLoginUrl("/");//配置用户登录请求 如果需要进行登录时Shiro就会转到这个请求进入登录页面
        shiroFilterFactoryBean.setSuccessUrl("/success");//配置登录成功以后转向的请求地址
        shiroFilterFactoryBean.setUnauthorizedUrl("/noPermission");//配置没有权限时转向的请求地址
        /**
         * 配置权限拦截规则
         */
        Map<String,String> filterChainMap=new LinkedHashMap<>();
        filterChainMap.put("/login","anon");//配置登录请求不需要认证 anon表示某个请求不需要认证
        filterChainMap.put("/logout","logout");//配置登录的请求，登出后会请求当前用户的内存
        //配置一个admin开头的所有请求需要登录 authc表示需要登录认证
        //roles[admin] 表示所有已admin开头的请求需要有admin的角色才可以使用
//        filterChainMap.put("/admin/**","authc,roles[admin]");
//        filterChainMap.put("/user/**","authc,roles[user]");//配置一个user开头的所有请求需要登录 authc表示需要登录认证


        //配置剩余的所有请求全部需要进行登录认证（注意：这个必须写在最后面），可选的配置
//        filterChainMap.put("/**","authc");
        //设置权限拦截规则
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainMap);
        return shiroFilterFactoryBean;
    }

    /**
     * 开启Shiro注解支持（例如@RequiresRoles()和@RequiresPermissions()）
     * shiro的注解需要借助Spring的AOP来实现
     * @return
     */
    @Bean
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator=new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    /**
     * 开启AOP的支持
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor=new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    /**
     * 配置Shiro标签与Thymeleaf的集成
     * @return
     */
    @Bean
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }

}
