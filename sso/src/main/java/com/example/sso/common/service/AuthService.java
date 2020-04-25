package com.example.sso.common.service;


import com.example.sso.common.param.UserAuthParam;

import java.util.Set;

public interface AuthService {
    /**
     * 获取用户登陆的授权token
     * @param loginInfo
     * @return
     */
    String loginAuth(UserAuthParam loginInfo);

    /**
     *是否已经授权
     * @return
     */
    Boolean isAuthed(String token, String requestUri);

    /**
     * 获取用户的权限
     * @return
     */
    Set<String> getPermissionSet();
    /**
     * 获取用户的角色
     * @return
     */
    Set<String> getRoleSet();

}