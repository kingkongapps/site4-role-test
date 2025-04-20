package com.example.keycloak.site4_role_test.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;

@Controller
public class ErrorController {
    @GetMapping(value = "/error/unauthorized")
    public String unauthorized(@RequestAttribute(value = "errorMessage",required = false) String errorMessage, Model model) {
        System.out.println("unauthorizedPage()...");
        //
        model.addAttribute("message", errorMessage != null ? errorMessage: "권한이 없습니다.");
        return "/unauthorized";
    }
}
