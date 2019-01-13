package com.oukele.shiroweb.controller;

import com.oukele.shiroweb.vo.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @RequestMapping(path = "/sublogin", method = RequestMethod.POST,produces = "application/json;charset=utf-8")
    public String login(User user) {
        // 获取当前主体
        Subject subject = SecurityUtils.getSubject();
        // 主体提交请求
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(), user.getPassword());
        try {
            //登陆 ，如果校验失败抛出异常
            subject.login(token);
        } catch (AuthenticationException e) {
            return e.getMessage();
        }

        return "登陆成功";
    }
    @RequestMapping(path = "/sublogin1", method = RequestMethod.GET,produces = "application/json;charset=utf-8")
    public String test (){
        return "登陆成功";
    }

}
