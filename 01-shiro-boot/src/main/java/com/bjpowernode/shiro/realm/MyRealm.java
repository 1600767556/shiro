package com.bjpowernode.shiro.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.HashSet;
import java.util.Set;

/**
 * 自定义的Realm来实现用户的认证和授权
 * <p>
 * 父类 AuthenticatingRealm 只支持用户认证(登录)
 */
public class MyRealm extends AuthorizingRealm {
    /**
     * 用户认证的方法 这个方法shiro自动调用
     *
     * @param authenticationToken 用户身份 存放用户账号密码
     * @return 用户登录成功的身份证明
     * @throws AuthenticationException 如果认证失败会抛出各种异常
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;

        String username = token.getUsername();
        String password = new String(token.getPassword());
        System.out.println("-------------");
        System.out.println("username: " + username + "  " + "password: " + password);

        if (!"admin".equals(username) && !"zhangsan".equals(username) && !"user".equals(username)) {
            throw new UnknownAccountException();//抛出账号错误异常
        }
        if ("zhangsan".equals(username)) {
            throw new LockedAccountException();//抛出账号锁定异常
        }
        //设置让当前登录用户中的密码进行加密
       /* HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("MD5");
        hashedCredentialsMatcher.setHashIterations(2);
        this.setCredentialsMatcher(hashedCredentialsMatcher);*/
        //对数据库中的密码进行加密

        // Object md5 = new SimpleHash("MD5", "123456", "", 3);
        //创建密码认证对象
        return new SimpleAuthenticationInfo(username, "e10adc3949ba59abbe56e057f20f883e", getName());
    }

    /**
     * 用户授权的方法
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("-----------授权了-----------");
        Object obj = principalCollection.getPrimaryPrincipal();//获取用户账号
        Set<String> roles = new HashSet<>();//定义角色的set集合 这个集合应该来自数据库
        //设置角色 这个操作应该是从数据库中获取数据
        if ("admin".equals(obj)) {
            roles.add("admin");
            roles.add("user");
        }
        if ("user".equals(obj)) {
            roles.add("user");
        }
        Set<String> premission = new HashSet<>();
        //设置权限 这里应该从数据库中获取信息
        if ("admin".equals(obj)){
            //添加一个权限admin:add  只是一种命名规则 没有特殊含义 表示admin下的add功能
            premission.add("admin:add");
        }
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setRoles(roles);//设置角色信息
        simpleAuthorizationInfo.setStringPermissions(premission);
        return simpleAuthorizationInfo;
    }

    public static void main(String[] args) {
        Object md5 = new SimpleHash("MD5", "123456", "", 1);
        System.out.println("123456使用md5加密一次： " + md5);
        Object md52 = new SimpleHash("MD5", "123456", "", 2);
        System.out.println("123456使用md5加密两次： " + md52);

        Object md53 = new SimpleHash("MD5", "123456", "admin", 1);
        System.out.println("123456使用md5 admin盐 加密一次： " + md53);

        Object md54 = new SimpleHash("MD5", "123456", "admin1", 1);
        System.out.println("123456使用md5 admin盐 加密一次： " + md54);
    }


}
