package com.bjpowernode.shiro.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
public class TestController {
    @RequestMapping("/")
    public String index() {
        return "login";
    }

    @RequestMapping("/login")
    public String login(String username, String password, Model model) {
        //获取权限操作对象 利用这个对象完成登录操作
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        //用户是否认证过
        if (!subject.isAuthenticated()) {
            //创建用户认证时的身份令牌
            UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username, password);
            try {

                /**
                 * 制定登陆 会自动调用Realm对象中的认定方法
                 */
                subject.login(usernamePasswordToken);
            } catch (UnknownAccountException e) {
                // e.printStackTrace();
                model.addAttribute("errorMessage", "账号错误!");
                return "login";
            } catch (LockedAccountException e) {
                // e.printStackTrace();
                model.addAttribute("errorMessage", "账号被锁定");
                return "login";
            } catch (IncorrectCredentialsException e) {
                // e.printStackTrace();
                model.addAttribute("errorMessage", "密码错误!");
                return "login";
            } catch (AuthenticationException e) {
                e.printStackTrace();
                model.addAttribute("errorMessage", "认证失败!");
                return "login";
            }

        }

        return "redirect:/success";
    }

    @RequestMapping("/logout")
    public String loginout() {
        Subject subject = SecurityUtils.getSubject();
        //登录当前账号 清空缓存
        subject.logout();
        return "redirect:/";
    }

    @RequestMapping("/success")
    public String success() {
        return "success";
    }

    @RequestMapping("/noPermission")
    public String noPermission() {
        return "noPermission";
    }


    /**
     * RequiresRoles shiro 提供的 用于标签类或者当前在访问是必须需要什么样的觉得
     * <p>
     * shiro中除了基于配置权限验证 以及注解的权限验证以外还支持基于方法调用的权限认证
     * Subject subject = SecurityUtils.getSubject();
     * String[] roles ={""};
     * subject.checkRoles(roles);//验证当前用户是否拥有指定的角色
     * String[] permissions ={""};
     * subject.checkPermissions(permissions);//验证当前用户是否拥有指定的权限
     *
     * @return
     */
    @RequiresRoles(value = {"admin"})
    @RequestMapping("/admin/test")
    @ResponseBody
    public String adminTest() {
        return "/admin/test请求";
    }


    @RequestMapping("/admin/test01")
    @ResponseBody
    public String adminTest01() {
        return "/admin/test01请求";
    }

    @RequiresPermissions(value = {"admin:add"})
    @RequiresRoles(value = {"admin"})
    @RequestMapping("/admin/add")
    @ResponseBody
    public String adminAdd() {

        return "/admin/add请求";
    }

    @RequiresRoles(value = {"user"})
    @RequestMapping("/user/test")
    @ResponseBody
    public String userTest() {
        return "/user/test请求";
    }

    /**
     * 配置自定义的异常拦截
     *
     * @return
     */
    @ExceptionHandler(value = {ShiroException.class})
    public String permissionError() {
        return "noPermission";
    }
}
