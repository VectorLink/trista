package com.example.demo.controller.config;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.example.demo.controller.LoginVerifyParam;
import com.example.demo.controller.UserLoginParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.util.CollectionUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class AuthInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse rep = (HttpServletResponse) response;
        //无需授权
        if (noNeedAuth(req)) {
            return true;
        }
        String token = request.getHeader("x-auth-token");//header方式
        //验权
        if (StringUtils.hasText(token)) {
            LoginVerifyParam params = new LoginVerifyParam();
            params.setToken(token);
            params.setRequestUri(request.getRequestURI());
            RestTemplate client = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.add("x-auth-token",token);
            HttpMethod method = HttpMethod.POST;
            // 以表单的方式提交
            headers.setContentType(MediaType.APPLICATION_JSON);
            //将请求头部和参数合成一个请求
            HttpEntity<LoginVerifyParam> requestEntity = new HttpEntity<LoginVerifyParam>(params, headers);
            //执行HTTP请求，将返回的结构使用ResultVO类格式化
            ResponseEntity<Boolean> rt = client.exchange("http://localhost:8082/verifyAuth", method, requestEntity, Boolean.class);
            if(rt.getStatusCode()!= HttpStatus.OK && rt.getBody()!=null && rt.getBody()){
                return true;
            }
            request.getRequestDispatcher("localhost:8082/tologin").forward(request, response);
            return false;
        }
        // 如果没有权限 则抛403异常 springboot会处理，跳转到 /error/403 页面
        response.sendError(HttpStatus.FORBIDDEN.value(), "无权限");
        return false;
    }

    /**
     * 无需授权
     *
     * @param req
     * @return
     */
    private boolean noNeedAuth(HttpServletRequest req) {
        if (req.getRequestURI().equals("/toLogin")) {
            return true;
        }
        //登陆
        if (req.getRequestURI().equals("/login")) {

            return true;
        }
        if(req.getRequestURI().equals("/favicon.ico")){
            return true;
        }
        return false;
    }

}