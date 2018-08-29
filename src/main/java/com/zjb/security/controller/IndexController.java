package com.zjb.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class IndexController {

    @RequestMapping(value = "/login")
    public String login() {
        return "login";
    }

    @RequestMapping(value = {"/home", "/"})
    public String home() {
        return "home";
    }

    @RequestMapping("/admin/admin")
    public String admin() {
        return "admin/admin";
    }

    @RequestMapping("/user/user")
    public String user() {
        return "user/user";
    }

    @RequestMapping("/public/public")
    public String publi() {
        return "public/public";
    }
}
