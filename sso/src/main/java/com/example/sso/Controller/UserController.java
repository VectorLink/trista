package com.example.sso.Controller;

import com.example.sso.Controller.param.LoginVerifyParam;
import com.example.sso.Controller.param.UserLoginParam;
import com.example.sso.shiro.UserDto;
import com.example.sso.shiro.UserService;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpResponse;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@Slf4j
public class UserController {
    @Value("${spring.redis.password}")
    private String redisPassword;
    @Autowired
    private UserService userService;
    @RequiresRoles("admin")
    @RequiresAuthentication
    @GetMapping("/test")
    public ResponseEntity test(){
        return ResponseEntity.ok("test");
    }

    @PostMapping(value = "/login")
    public ResponseEntity <String> login(@RequestBody UserLoginParam loginInfo, HttpServletRequest request, HttpServletResponse response){
        //获取请求主体
        Subject subject = SecurityUtils.getSubject();
        try {
            //将用户请求参数封装
            UsernamePasswordToken token = new UsernamePasswordToken(loginInfo.getName(), loginInfo.getPassword());
            /**直接提交给Shiro处理，进入内部验证，如果验证失败，返回AuthenticationException，如果通过，就将全部认证信息关联到
             * 此Subject上，subject.getPrincipal()将非空，且subject.isAuthenticated()为True*/
            subject.login(token);
            log.info(">>AdminController.login OK!");
            UserDto user = (UserDto) subject.getPrincipal();
            String newToken = userService.generateJwtToken(user.getUsername());
            //写入响应信息返回
            response.setHeader("x-auth-token", newToken);
            return ResponseEntity.ok(newToken);
        } catch (AuthenticationException e) {
            // 如果校验失败，shiro会抛出异常，返回客户端失败
            log.error("User {} login fail, Reason:{}", loginInfo.getName(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            log.error("erro password {},{}",redisPassword,e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping(value = "/logout")
    public ResponseEntity logout(){
        Subject subject = SecurityUtils.getSubject();
        if (subject.getPrincipals() != null){
            UserDto userDto = (UserDto) subject.getPrincipals().getPrimaryPrincipal();
            userService.deleteLogInfo(userDto.getUsername());
        }
        //务必不能少
        SecurityUtils.getSubject().logout();
        return ResponseEntity.ok().build();
    }

    @PostMapping(value = "/verifyAuth")
    public ResponseEntity<Boolean> admin2(@RequestBody LoginVerifyParam param, HttpServletRequest request, HttpServletResponse response){
        if(param.getRequestUri().contains("allow")){
            return  ResponseEntity.ok(true);
        }
        return  ResponseEntity.ok(false);

    }


    @RequiresRoles("manager")
    @GetMapping("/manager")
    public ResponseEntity test(HttpServletRequest request, HttpServletResponse response){
        return ResponseEntity.ok(request.getHeader("x-auth-token"));
    }

    @GetMapping("/admin")
    public ResponseEntity test2(HttpServletRequest request, HttpServletResponse response){
        return ResponseEntity.ok(request.getHeader("x-auth-token"));
    }


}
