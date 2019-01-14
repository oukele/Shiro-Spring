package com.oukele.shiroweb.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;

import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;

import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CustomRealm extends AuthorizingRealm {
  // 模拟数据库
    Map<String,String> userMap = new HashMap<>(16);
    {
        userMap.put("Mark","123456");
        // 设置 realm 名称
        super.setName("customRealm");
         // 密码 123456 经过 MD5 加密一次
        userMap.put("oukele", "4ed40bd548567831b876b9dd444a3525");
    }

    /*
    *  权限 认证
    * */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        //从主体信息 获取 用户
        String userName = (String) principals.getPrimaryPrincipal();
        // 通过用户 获取角色信息
        Set<String> roles = getRolesByUsername(userName);
        // 通过用户 获取权限
        Set<String> permissions = getPermissionsByUsername(userName);
        // 权限认证信息
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        // 设置权限
        simpleAuthorizationInfo.setStringPermissions(permissions);
        //设置 角色
        simpleAuthorizationInfo.setRoles(roles);
        // 任何认证信息
        return simpleAuthorizationInfo;
    }
    /*
    * 模拟权限
    * */
    private Set<String> getPermissionsByUsername(String userName) {
        Set<String> sets = new HashSet<>();
        sets.add("user:delete");
        sets.add("user:add");
        return sets;
    }
    /*
    *  模拟角色
    * */
    private Set<String> getRolesByUsername(String userName) {
        Set<String> sets = new HashSet<>();
        sets.add("admin");
        sets.add("user");
        return sets;
    }

    /*
    * 登陆认证
    * */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        //1、从主体传过来的信息，从中获取用户名
        String userName = (String) token.getPrincipal();
        //2、通过用户名去数据库获取凭证
        String password = getPasswordByUsername(userName);
        String password1 = (String) token.getCredentials();

        System.out.println( password.equals(password1) );

        // 如果用户名不存在
        if (password == null){
            return  null;
        }
        // 认证信息
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(userName,password,"customRealm");
        // 设置加密的 盐（用户）
        authenticationInfo.setCredentialsSalt(ByteSource.Util.bytes(userName));
        // 返回认证信息
        return authenticationInfo;
    }

    /*
    * 模拟数据库  通过用户名获取凭证
    * */
    private String getPasswordByUsername(String userName) {
        return userMap.get(userName);
    }

}
