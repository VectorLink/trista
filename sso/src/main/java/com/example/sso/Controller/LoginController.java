package com.example.sso.Controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class LoginController {
    @GetMapping("toLogin")
    public ModelAndView toLogin(){
        return new ModelAndView("toLogin");
    }

}
