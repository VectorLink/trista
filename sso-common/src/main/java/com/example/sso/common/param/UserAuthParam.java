package com.example.sso.common.param;

import java.io.Serializable;

public class UserAuthParam implements Serializable {
    private String username;
    private String password;

    public UserAuthParam(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public UserAuthParam(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
