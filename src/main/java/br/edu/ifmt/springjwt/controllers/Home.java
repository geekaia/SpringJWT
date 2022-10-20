package br.edu.ifmt.springjwt.controllers;



import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class Home {


    @GetMapping("/")
    public String home(Principal principal) {
        return "Username: "+principal.getName();
    }


}
