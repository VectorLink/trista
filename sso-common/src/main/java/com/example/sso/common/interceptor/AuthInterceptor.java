package com.example.sso.common.interceptor;

import com.example.sso.common.anno.RequiredPermission;
import com.example.sso.common.anno.RequiredRoles;
import com.example.sso.common.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Set;

public class AuthInterceptor implements HandlerInterceptor {

    @Autowired
    private AuthService authService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse rep = (HttpServletResponse) response;
        //无需授权
        if(noNeedAuth(req)){
            return true;
        }
        String token = request.getHeader("x-auth-token");//header方式
        // 验证权限
        if (authService.isAuthed(token, req.getRequestURI())) {
            return true;
        }
        //  null == request.getHeader("x-requested-with") TODO 暂时用这个来判断是否为ajax请求
        // 如果没有权限 则抛403异常 springboot会处理，跳转到 /error/403 页面
        response.sendError(HttpStatus.FORBIDDEN.value(), "无权限");
        return false;
    }

    /**
     * 是否有权限
     *
     * @param handler
     * @return
     */
    private boolean hasPermission(Object handler) {
        if (handler instanceof HandlerMethod) {
            HandlerMethod handlerMethod = (HandlerMethod) handler;
            // 获取方法上的注解
            RequiredPermission requiredPermission = handlerMethod.getMethod().getAnnotation(RequiredPermission.class);
            // 如果方法上的注解为空 则获取类的注解
            if (requiredPermission == null) {
                requiredPermission = handlerMethod.getMethod().getDeclaringClass().getAnnotation(RequiredPermission.class);
            }
            // 如果标记了注解，则判断权限
            if (requiredPermission != null && StringUtils.hasText(requiredPermission.value())) {
                // redis或数据库 中获取该用户的权限信息 并判断是否有权限
                Set<String> permissionSet = authService.getPermissionSet();
                if (CollectionUtils.isEmpty(permissionSet) ){
                    return false;
                }
                return permissionSet.contains(requiredPermission.value());
            }
            RequiredRoles requiedRoles = handlerMethod.getMethod().getAnnotation(RequiredRoles.class);
            if (requiedRoles == null) {
                requiedRoles = handlerMethod.getMethod().getDeclaringClass().getAnnotation(RequiredRoles.class);
            }
            // 如果标记了注解，则判断权限
            if (requiedRoles != null && StringUtils.hasText(requiedRoles.value())) {
                // redis或数据库 中获取该用户的权限信息 并判断是否有权限
                Set<String> roleSet= authService.getPermissionSet();
                if (CollectionUtils.isEmpty(roleSet) ){
                    return false;
                }
                return roleSet.contains(requiedRoles.value());
            }
        }
        return true;
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
