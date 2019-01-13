package com.oukele.shiroweb;


import com.oukele.shiroweb.realm.CustomRealm;
import com.oukele.shiroweb.vo.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

public class CustomRealmTest {

    @Test
    public void test() {
        // 创建 自定义 realm 对象
        CustomRealm customRealm = new CustomRealm();
        // 构建 securityManager 环境
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        //将自定义 realm 设置到 securityManager 环境中
        securityManager.setRealm(customRealm);

        // 主体 提交 认证请求
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();

        User user = new User();
        user.setUsername("oukele");
        user.setPassword("123456");
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(), user.getPassword());

        subject.login(token);
        System.out.println("登陆状态:" + subject.isAuthenticated());

        System.out.println("登陆账号:" + subject.getPrincipal());
        subject.checkRole("admin");

        subject.checkPermissions("user:add","user:delete");

    }
}
