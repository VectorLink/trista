package com.example.sso.shiro;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {
    private String username;
    private String salt;
    private String password;
    private Long userId;
    private String encryptPwd;
    private List<String> roles;
}
