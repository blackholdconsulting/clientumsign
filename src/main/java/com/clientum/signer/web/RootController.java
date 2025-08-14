package com.clientum.signer.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class RootController {

  @GetMapping({"/", "/login"})
  public String redirectToSwagger() {
    return "redirect:/swagger-ui/index.html";
  }
}
