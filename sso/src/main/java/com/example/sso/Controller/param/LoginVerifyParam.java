package com.example.sso.Controller.param;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginVerifyParam {
    private String requestUri;
    private String token;
}
