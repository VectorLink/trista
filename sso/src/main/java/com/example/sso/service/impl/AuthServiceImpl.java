package com.example.sso.service.impl;


import com.example.sso.common.param.UserAuthParam;
import com.example.sso.common.service.AuthService;
import com.example.sso.shiro.UserDto;
import com.example.sso.shiro.UserService;
import io.lettuce.core.internal.LettuceSets;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

/**
 * @Classname AuthService
 * @Description TODO
 * @Author xiexiaobiao
 * @Date 2019-09-08 10:05
 * @Version 1.0
 **/
@Service
public class AuthServiceImpl implements AuthService {

    private Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private UserService userService;

    public AuthServiceImpl(UserService userService){
        this.userService = userService;
    }

    @Override
    public String loginAuth(UserAuthParam loginInfo) {
        Subject subject = SecurityUtils.getSubject();
        try{
            UsernamePasswordToken token = new UsernamePasswordToken(loginInfo.getUsername(),loginInfo.getPassword());
            subject.login(token);
            UserDto userDto = (UserDto) subject.getPrincipals().getPrimaryPrincipal();
            String newToken = userService.generateJwtToken(userDto.getUsername());
            return newToken;
        } catch (AuthenticationException e) {
            logger.error("User {} loginAuth fail, Reason:{}", loginInfo.getUsername(), e.getMessage());
        } catch (Exception e) {
            logger.error("User {} loginAuth fail, Reason:{}", loginInfo.getUsername(), e.getMessage());
        }
        return null;
    }

    @Override
    public Boolean isAuthed(String token, String requestUri) {
        Subject subject = SecurityUtils.getSubject();

        return null;
    }

    @Override
    public Set<String> getPermissionSet() {
        Subject subject = SecurityUtils.getSubject();
        return new HashSet<String>();
    }

    @Override
    public Set<String> getRoleSet() {
        return  new HashSet<String>();
    }

}
