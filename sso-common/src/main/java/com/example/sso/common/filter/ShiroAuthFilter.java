package com.example.sso.common.filter;

import com.alibaba.fastjson.JSON;
import com.example.sso.common.dto.ResultInfo;
import com.example.sso.common.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

@Component
@Slf4j
public abstract class ShiroAuthFilter implements Filter , AuthService{
    @Override
    public void destroy() {

    }
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse rep = (HttpServletResponse) response;

        //无需授权登陆
        if(noNeedAuth(req)){
            chain.doFilter(request, response);
            return;
        }


        //设置允许跨域的配置
        // 这里填写你允许进行跨域的主机ip（正式上线时可以动态配置具体允许的域名和IP）
        rep.setHeader("Access-Control-Allow-Origin", "*");
        // 允许的访问方法
        rep.setHeader("Access-Control-Allow-Methods","POST, GET, PUT, OPTIONS, DELETE, PATCH");
        // Access-Control-Max-Age 用于 CORS 相关配置的缓存
        rep.setHeader("Access-Control-Max-Age", "3600");
        rep.setHeader("Access-Control-Allow-Headers","token,Origin, X-Requested-With, Content-Type, Accept");


        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        String token = req.getHeader("x-auth-token");//header方式
        ResultInfo resultInfo = new ResultInfo();
        boolean isFilter = false;
        String method = ((HttpServletRequest) request).getMethod();
        if (method.equals("OPTIONS")) {
            rep.setStatus(HttpServletResponse.SC_OK);
        }else{
            

            if (null == token || token.isEmpty()) {
                resultInfo.setCode(HttpStatus.UNAUTHORIZED.value());
                resultInfo.setMsg("用户授权认证没有通过!客户端请求参数中无token信息");
            } else {

                if (isAuthed(token, req.getRequestURI())) {
                    resultInfo.setCode(HttpStatus.OK.value());
                    resultInfo.setMsg("用户授权认证通过!");
                    isFilter = true;
                } else {
                    resultInfo.setCode(HttpStatus.UNAUTHORIZED.value());
                    resultInfo.setMsg("用户授权认证没有通过!客户端请求参数token信息无效");
                }
            }
            if (resultInfo.getCode() == HttpStatus.UNAUTHORIZED.value()) {// 验证失败
                PrintWriter writer = null;
                OutputStreamWriter osw = null;
                try {
                    osw = new OutputStreamWriter(response.getOutputStream(),
                            "UTF-8");
                    writer = new PrintWriter(osw, true);
                    String jsonStr = JSON.toJSONString(resultInfo);
                    writer.write(jsonStr);
                    writer.flush();
                    writer.close();
                    osw.close();
                } catch (UnsupportedEncodingException e) {
                    log.error("过滤器返回信息失败:" + e.getMessage(), e);
                } catch (IOException e) {
                    log.error("过滤器返回信息失败:" + e.getMessage(), e);
                } finally {
                    if (null != writer) {
                        writer.close();
                    }
                    if (null != osw) {
                        osw.close();
                    }
                }
                return;
            }

            if (isFilter) {
                log.info("token filter过滤ok!");
                chain.doFilter(request, response);
            }
        }


    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {

    }

    /**
     * 无需授权
     * @param req
     * @return
     */
    private boolean noNeedAuth(HttpServletRequest req ){
        if(req.getRequestURI().equals("/login")){
            return true;
        }
        return false;
    }

}