package com.bjpowernode.shiro.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.HashSet;
import java.util.Set;

/**
 * 自定义的Realm用来实现用户的认证和授权
 * 父类AuthenticatingRealm 只做用户认证（登录）
 *
 */
public class MyRealm extends AuthorizingRealm {

    /**
     * 用户认证的方法 这个方法不能手动调用Shiro会自动调用
     * @param authenticationToken 用户身份 这里存放着用户的账号和密码
     * @return 用户登录成功后的身份证明
     * @throws AuthenticationException  如果认证失败Shiro会抛出各种异常
     * 常用异常
     * UnknownAccountException 账号不存在
     * AccountException        账号异常
     * LockedAccountException  账户锁定异常（冻结异常）
     * IncorrectCredentialsException 密码认证失败以后Shiro自动抛出表示密码错误
     * 注意：
     *   如果这些异常不够用可以自定义异常类并继承Shiro认证异常父类AuthenticationException
     *
     */
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        UsernamePasswordToken token= (UsernamePasswordToken) authenticationToken;
        String username=token.getUsername();//获取页面中传递的用户账号
        String password=new String(token.getPassword());//获取页面中的用户密码实际工作中基本不需要获取
        System.out.println(username+" -----  "+password);
        /**
         * 认证账号，这里应该从数据库中获取数据，
         * 如果进入if表示账号不存在要抛出异常
         */
        if(!"admin".equals(username)&&!"zhangsan".equals(username)&&!"user".equals(username)){
            throw new UnknownAccountException();//抛出账号错误的异常
        }
        /**
         * 认证账号，这里应该根据从数据库中获取数来的数据进行逻辑判断，判断当前账号是否可用
         * IP是否允许等等，根据不同的逻可以抛出不同的异常
         */
        if("zhangsan".equals(username)){
            throw new LockedAccountException();//抛出账号锁定异常
        }

        /**
         * 数据密码加密主要是防止数据在浏览器到后台服务器之间的数据传递时被篡改或被截获，因此应该在前台到后台的过程中
         * 记行加密，而我们这里的加密一个时间将浏览器中获取后台的明码加密和对数据库中的数据进行加密
         * 这就丢失了数据加密的意义 因此不建议在这里进行加密，应该在页面传递传递时进行加密
         * 注意：
         *   建议浏览器传递数据时就是加密数据，数据库中存在的数据也是加密数据，我们必须保证前段传递的数据
         *   和数据主库中存放的数据加密次数以及盐一会规则都是完全相同的否则认证失败
         */
        //设置让当前登录用户中的密码数据进行加密
//        HashedCredentialsMatcher credentialsMatcher=new HashedCredentialsMatcher();
//        credentialsMatcher.setHashAlgorithmName("MD5");
//        credentialsMatcher.setHashIterations(2);
//        this.setCredentialsMatcher(credentialsMatcher);
//        //对数据库中的密码进行加密
//        Object obj=new SimpleHash("MD5","123456","",3);

        /**
         * 创建密码认证对象，由Shiro自动认证密码
         * 参数 1 数据库中的账号（或页面账号均可）
         * 参数 2 为数据中读取数据来的密码
         * 参数 3 为当前Realm的名字
         * 如果密码认证成功则返回一个用户身份对象，如果密码认证失败Shiro会抛出异常IncorrectCredentialsException
         */
        return new SimpleAuthenticationInfo(username,"e10adc3949ba59abbe56e057f20f883e",getName());
    }


    /**
     * 用户授权的方法， 当用户认证通过每次访问需要授权的请求时都需要执行这段代码来完后曾授权操作
     * 这里用该查询数据库来获取当前用户的所有角色和权限，并设置到shiro中
     * @param principalCollection
     * @return
     */
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("--------------授权了------------------");
        Object obj=principalCollection.getPrimaryPrincipal();//获取用户的账号，根据账号来从数据库中获取数据
        //定义用户角色的set集合这个集合应该来自数据库
        //注意：由于每次点击需要授权的请求时，Shiro都会执行这个方法，因此如果这里的数据时来自于数据库中的
        //     那么一定要控制好不能每次都从数据库中获取数据这样效率太低了
        Set<String> roles=new HashSet<String>();
        //设置角色，这里个操作应该是用数据中读取数据
        if("admin".equals(obj)){
            roles.add("admin");
            roles.add("user");
        }
        if("user".equals(obj)){
            roles.add("user");
        }
        Set<String>permissions=new HashSet<>();
        //设置权限，这里个操作应该是用数据中读取数据
        if("admin".equals(obj)){
            //添加一个权限admin:add 只是一种命名风格表示admin下的add功能
            permissions.add("admin:add");
        }

        SimpleAuthorizationInfo info=new SimpleAuthorizationInfo();
        info.setRoles(roles);//设置角色信息
        info.setStringPermissions(permissions);//设置用户的权限信息
        return info;
    }

    public static void main(String[] args) {
        //使用Shiro提供的工具类对数据进行加密
        //参数 1 为加密算法名 我们使用MD5这是一个不可逆的加密算法
        //参数 2 为需要加密的数据
        //参数 3 加密的盐值 用于改变加密结果的 不同的盐加密的数据是不一致的
        //参数 4 为加密的次数
        Object obj=new SimpleHash("MD5","123456","",1);
        System.out.println("123456使用MD5加密1次----   "+obj);
        Object obj2=new SimpleHash("MD5","123456","",2);
        System.out.println("123456使用MD5加密2次----   "+obj2);
        Object obj3=new SimpleHash("MD5","e10adc3949ba59abbe56e057f20f883e","",1);
        System.out.println("123456使用MD5加密1次后在对这个数据加密1次----   "+obj3);

        Object obj4=new SimpleHash("MD5","123456","admin",1);
        System.out.println("123456使用MD5 加盐admin 加密1次----   "+obj4);
        Object obj5=new SimpleHash("MD5","123456","admin1",1);
        System.out.println("123456使用MD5 加盐admin1 加密1次----   "+obj5);
    }


}
