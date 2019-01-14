# Shiro-Spring
shiro的第二个示例

#### Java 中使用 shiro 

1、架构

```html
shiro 是一个强大的简单易用的Java安全框架，主要用来更便捷的认证，授权，加密，会话管理。
```

![](https://images2018.cnblogs.com/blog/839956/201805/839956-20180516145545972-1276776368.png)



shiro 除了 基本特征，授权，会话管理，加密之外，还有许多额外的特性。

从大的角度看，Shiro 有三个主要的概念：Subject，SecurityManager ,Realms 从一幅图可以看这些原件之间的交互。

![](https://images2018.cnblogs.com/blog/839956/201805/839956-20180516145627569-266277541.png)

```html
Subject：主体，代表了当前"用户"，这个用户不一定是一个具体的人，与当前应用交互的任何东西都是Subject，比如网络爬虫，机器人等；即一个抽象概念：所有Subject都绑定到SecurityManager,与Subject的所有交互都会委托给SecurityManager;可以把Subject认为是一个门面；SecurityManager才是实际的执行者。
```

```html
SecurityManager:安全管理器；即所有与安全有关的操作都会与SecurityManager交互；且它管理着所有Subject；可以看出它是Shiro的核心，它负责与后边介绍的其他组件进行交互，就好比如SpringMVC中的DispatcherServlet前端控制器。
```

```html
Realm：域，Shiro 从 realm 获取安全数据（如 用户、角色、权限），就是说SecurityManager要验证用户身份，那么它需要从Realm获取相对应的用户进行比较确定用户身份是否合法；也需要从Realm 得到 用户相应的 角色\权限 进行验证用户是否能进行操作；可以把Realm 看出 DataSource，即安全数据源。
```

#### 2、名词解释

```html
Authentication : 身份认证/登陆 ，验证用户是不是拥有相应的身份
```

```html
Authorization：授权，即权限验证，验证某个已认证的用户是否拥有某个权限；即判断用户是否能做的事。
比如：验证某个用户是否拥有某个角色。或者细粒度的验证某个用户对某个资源是否具有某个权限
```

```html
Session Manager ： 会话管理，即用户登录后就是一次会话，在没有退出之前，它的所有信息都在会话中；会话可以是 普通JavaSE环境的，也可以是Web环境的。
```

```html
Cryptography : 加密，保护数据安全，如密码加密存储到数据库，而不是明文存储
```

```html
Web Support ： Web支持 可以非常容易的集成到Web环境。
```

```html
Caching ： 缓存，比如用户登录后，其用户信息，拥有的角色/权限 不必每次去查，这样可以提高效率。
```

```html
Concurrency : shiro 支持 多线程应用程序的并发验证，即如在一个线程中开启另一线程，能把权限自动传播过去。
```

```html
Testing : 提供测试支持。
```

```html
Run As ： 允许一个用户假装为另一个用户（如果他们允许）的身份进行访问。
```

```html
Remember Me ： 记住我，这个是非常 常见的功能，即一次登录后，下次再来的话就不用登录了。
```

##### 记住一点，Shiro不会去维护用户、维护权限；这些需要我们自已去设计/提供；然后通过相应的接口注入给Shiro即可。

#### spring MVC + shiro 

步骤：

- 创建 web 的 maven项目

- pom.xml 添加依赖

  ```xml
  <dependency>
     <groupId>org.springframework</groupId>
     <artifactId>spring-context</artifactId>
     <version>5.1.3.RELEASE</version>
   </dependency>
    
   <dependency>
     <groupId>org.springframework</groupId>
     <artifactId>spring-webmvc</artifactId>
     <version>5.1.3.RELEASE</version>
   </dependency>
    
   <dependency>
     <groupId>org.apache.shiro</groupId>
     <artifactId>shiro-core</artifactId>
     <version>1.4.0</version>
   </dependency>
  <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-spring</artifactId>
      <version>1.4.0</version>
    </dependency>
    
    <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-web</artifactId>
      <version>1.3.2</version>
    </dependency>
  ```

- resources目录中，新建spring-root.xml 与 springmvc.xml 配置文件

  - spring-root.xml

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <beans xmlns="http://www.springframework.org/schema/beans"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    
        <!--创建 shiro -->
        <bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
            <!--配置 securityManager 对象-->
            <property name="securityManager" ref="securityManager"/>
            <!-- 登陆页的URL -->
            <property name="loginUrl" value="login.html"/>
            <!-- 未认证的跳转URK -->
            <property name="unauthorizedUrl" value="403.html"/>
            <!--过滤器链-->
            <property name="filterChainDefinitions">
                <!-- anon 不需要验证、authc需要认证 -->
                <!-- 过滤器链 按照从上到下的规则 -->
                <value>
                    /login.html = anon
                    /sublogin = anon
                    /sublogin1 = anon
                    /* = authc
                </value>
            </property>
        </bean>
        <!-- 创建 SecurityManager 对象-->
        <bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
            <property name="realm" ref="realm"/>
        </bean>
        <!--自定义Realm-->
        <bean id="realm" class="com.oukele.shiroweb.realm.CustomRealm">
            <!-- 配置 加密管理 -->
            <property name="credentialsMatcher" ref="credentialsMatcher"/>
        </bean>
        <!-- shiro 加密管理对象 （数据库存储的是 加密后的 密码 ） -->
        <bean class="org.apache.shiro.authc.credential.HashedCredentialsMatcher" id="credentialsMatcher">
            <!-- 设置 加密的算法为 md5 -->
            <property name="hashAlgorithmName" value="md5"/>
            <!--设置 加密的次数 为 1 次 -->
            <property name="hashIterations" value="1"/>
        </bean>
    
    </beans>
    ```

  - springmvc.xml

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <beans xmlns="http://www.springframework.org/schema/beans"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:context="http://www.springframework.org/schema/context"
           xmlns:mvc="http://www.springframework.org/schema/mvc"
           xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/context http://www.springframework.org/schema/context/spring-context.xsd http://www.springframework.org/schema/mvc http://www.springframework.org/schema/mvc/spring-mvc.xsd http://www.springframework.org/schema/aop http://www.springframework.org/schema/aop/spring-aop.xsd">
        <!-- 扫描 spring 组件 -->
        <context:component-scan base-package="com.oukele.shiroweb.controller"/>
        <!-- 启用 spring 注解 -->
        <mvc:annotation-driven/>
        <!-- 将静态资源排除( 不经过SpringMVC 控制器) -->
        <mvc:resources mapping="/*" location="/"/>
    
    </beans>
    ```

- 新建一个类继承 AuthorizingRealm 类（自定义规则）

  ```java
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
          // 密码 为 123456 （经过 MD5 加密一次）
          userMap.put("oukele","4ed40bd548567831b876b9dd444a3525");
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
  
  ```

- 新建 UserController 类 

  ```java
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
  
  ```

- webapp 文件中 新建 login.html 文件

  ```html
  <!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8">
      <title>Title</title>
  </head>
  <body>
  <form action="/sublogin" method="post">
      用户名：<input type="text" name="username" /><br/>
      密码：<input type="password" name="password"><br/>
      <input type="submit" value="登陆">
  </form>
  </body>
  </html>
  ```

- webapp文件夹 目录中 WEB-INF 文件夹 中 的 web.xml

  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
           version="4.0">
  
      <display-name> shiro-web </display-name>
  
      <!--配置spring容器-->
      <context-param>
          <param-name>contextConfigLocation</param-name>
          <param-value>classpath:spring/spring-root.xml</param-value>
      </context-param>
      <listener>
          <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
      </listener>
  
      <!--配置spring mvc 容器-->
      <servlet>
          <servlet-name>webs</servlet-name>
          <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
          <init-param>
              <param-name>contextConfigLocation</param-name>
              <param-value>classpath:spring/springmvc.xml</param-value>
          </init-param>
      </servlet>
      <servlet-mapping>
          <servlet-name>webs</servlet-name>
          <url-pattern>/</url-pattern>
      </servlet-mapping>
  
      <filter>
          <filter-name>shiroFilter</filter-name>
          <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
      </filter>
      <filter-mapping>
          <filter-name>shiroFilter</filter-name>
          <url-pattern>/*</url-pattern>
      </filter-mapping>
  
  </web-app>
  ```

#### 总结

- 创建Maven的Web项目，创建完毕之后，按照Maven的规范创建出相应的Java源码文件以及相应的test测试目录。并且将web-info下的文件删除。

- 设置java文件夹以及resources文件夹分别为源码类型以及资源文件类型，具体可以点击文件夹右键，找到Mark Dirctory as选择。

- 在resources中创建spring文件夹，并且创建spring.xml以及spring-mvc.xml文件。

- 在web-info中创建web.xml文件。一般的idea不可创建出web.xml文件，所以此时按照网上给的方法，直接选择菜单中的File---Project Stru----Facts 第一个空白点击处，添加web.xml文件。点击确定即可。路径要写对，是在web-info下。此种方法如果不行，则需要手动写入web.xml文件。

- 其次在Maven的pom.xml文件中引入相应的spring、springmvc 、shiro 、shiro-spring、shiro-web的jar包，注意必须版本保持匹配，否则启动容易报404错误，我就是因为这个问题。如下是pom.xml文件引入的包。

- 在相应的resources资源文件下建立spring文件夹，在spring-mvc.xml文件中写入扫描文件以及驱动、过滤的标签，如下：

  - ```xml
    <context:component-scan base-package="com.imooc.controller"/>
    <mvc:annotation-driven />
    <mvc:resources mapping="/*" location="/"/>
    ```

- 在spring.xml文件中，写入相应的自定义的Realm的bean标签、加密的Hashed的bean标签（注入到Realm中）、写入默认的web的权限管理的bean标签（注入Realm）、写入ShiroFilterFactoryBean的bean标签（将web的权限管理注入进去）即可。

  - 此外ShiroFilter的bean标签里面，还可以规定loginurl的值，即登录的页面，unauthor..登录失败没权限访问的页面，filterChainDefinitions过滤链，（过滤链里面可以以a=b的形式进行过滤，例：/login.html = anon 表示在访问login.html页面的时候不需要任何权限，anon表示无需权限，authc代表必须认证通过才能访问，一般链是从上往下匹配，只要匹配的相应结果，则直接返回。所以一般把/*=authc放在最后。）

- 之后基本上就是写入controller以及html网页即可。之后启动tomcat自动访问，其中关于编码的问题需要在@RequestMapping中设置produces="application/json;charset=utf-8"的形式即可。


