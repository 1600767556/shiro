package com.bjpowernode.shiro.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.servlet.ShiroFilter;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TestController {

    @RequestMapping("/")
    public String index(){
        return "login";
    }
    @RequestMapping("/login")
    public  String login(String username, String password, Model model){
        //获取权限操作对象，利用这个对象来完成登录操作
        Subject subject= SecurityUtils.getSubject();
        //登出,进入这个请求用户一定是要完成用户登录功能，因此我们就先登出，否则Shiro会有缓存不能重新登录
        //注意：这么做如果用户是误操作会重新指定一次登录请求
        subject.logout();
        //用户是否认证过（是否登录过），进入if表示用户没有认证过需要进行认证
        if(!subject.isAuthenticated()){
            //创建用户认证时的身份令牌，并设置我们从页面中传递过来的账号和密码
            UsernamePasswordToken usernamePasswordToken=new UsernamePasswordToken(username,password);
            try {
                /**
                 * 指定登录，会自动调用我们Realm对象中的认证方法
                 * 如果登录失败会抛出各种异常
                 */
                subject.login(usernamePasswordToken);
            } catch (UnknownAccountException e) {
//                e.printStackTrace();
                model.addAttribute("errorMessage","账号错误！");
                return "login";
            }catch (LockedAccountException e) {
//                e.printStackTrace();
                model.addAttribute("errorMessage","账号被锁定！");
                return "login";
            }catch (IncorrectCredentialsException e) {
//                e.printStackTrace();
                model.addAttribute("errorMessage","密码错误");
                return "login";
            }catch (AuthenticationException e) {
                e.printStackTrace();
                model.addAttribute("errorMessage","认证失败！");
                return "login";
            }
        }

        return "redirect:/success";
    }

    @RequestMapping("/logout")
    public  String logout(){
        Subject subject=SecurityUtils.getSubject();
        //登录当前账号，清空Shiro当前用户的缓存，否则无法重新登录
        subject.logout();
        return "redirect:/";
    }
    @RequestMapping("/success")
    public String loginSuccess(){
        return "success";
    }
    @RequestMapping("/noPermission")
    public String noPermission(){
        return "noPermission";
    }



    /**
     *@RequiresRoles 这个注解是Shiro提供的 用于标签类或当前当前在访问是必须需要什么样的角色
     * 属性
     *   value 取值为String 数组类型 用于指定访问时所需要的一个或多个角色名
     *   logical 取值为Logical.AND或Logical.OR，当指定多个角色时可以使用AND或OR来表示并且和或的意思默认值为AND
     *           表示当前用户必须同时拥有多个角色才可以访问这个方法
     *
     * 注意：Shiro中出列基于配置权限验证以及注解的权限验证意外还支持基于方法调用的权限验证例如
     * Subject subject=SecurityUtils.getSubject();
     *  String[] roles={""};
     *  subject.checkRoles(roles);//验证当前用户是否拥有指定的角色
     *  String[] permissions={""};
     *  subject.checkPermissions(permissions);//验证当前用户是否拥有指定的权限
     */
    @RequiresRoles(value = {"admin"})
    @RequestMapping("/admin/test")
    public @ResponseBody String adminTest(){
        return "/admin/test请求";
    }
    @RequestMapping("/admin/test01")
    public @ResponseBody String adminTest01(){
        return "/admin/test01请求";
    }
    @RequiresRoles(value = {"admin"})
    /**
     * @RequiresPermissions 用于判断当前用户是否有指定的一个或多个权限用法与RequiresRoles相同
     */
    @RequiresPermissions(value={"admin:add"})
    @RequestMapping("/admin/add")
    public @ResponseBody String adminAdd(){

        return "/admin/add请求";
    }
    @RequiresRoles(value = {"user"})
    @RequestMapping("/user/test")
    public @ResponseBody String userTest(){
        return "/user/test请求";
    }

    /**
     * 配置自定义的异常拦截，需要拦截AuthorizationException 异常或ShiroException异常
     * 注意：当前Shiro出现权限验证失败以后会抛出异常，因此必须要写一个自定义的异常拦截
     * 否则我发正常的转型到我们的错误页面
     * @return
     */
    @ExceptionHandler(value={AuthorizationException.class})
    public String permissionError(Throwable throwable){
        //转向到没有权限的视图页面，可以利用参数throwable将错误信息写入浏览器中
        //实际工作工作中应该根据参数的类型来判断具体是什么异常，然后根据同的异常来为用户提供不同的
        //提示信息
        return "noPermission";
    }
}
