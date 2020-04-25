package com.example.demo.controller;

import com.sun.deploy.net.HttpResponse;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@Controller
public class HelloController {
    @GetMapping("/hi")
    public String hi(){
        return "hi";
    }
    @GetMapping("/allow")
    public String allow(){
        return "hi";
    }

    @RequestMapping("/toLogin")
    public String  toLogin(){
        return "/toLogin";
    }
    @RequestMapping("/login")
    public String login(String name, String password, HttpServletRequest request, HttpServletResponse response){
        User param = new User();
        param.setName(name);
        param.setPassword(password);

        RestTemplate client = new RestTemplate();
        HttpMethod method = HttpMethod.POST;
        //将请求头部和参数合成一个请求
        HttpEntity<User> requestEntity = new HttpEntity<User>(param);
        //执行HTTP请求，将返回的结构使用ResultVO类格式化
        ResponseEntity<String> rt = client.exchange("http://localhost:8082/login", method, requestEntity, String.class);
        if(rt.getStatusCode() == HttpStatus.OK) {
            request.setAttribute("token", rt.getBody());
            response.setHeader("x-auth-token",rt.getBody());
        }
        return "loginSuccess";
    }
}

