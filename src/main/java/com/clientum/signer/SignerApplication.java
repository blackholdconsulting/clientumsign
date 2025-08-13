package com.clientum.signer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = {
    "com.clientum.signer.controller",
    "com.clientum.signer.service",
    "com.clientum.signer.config"
})
public class SignerApplication {
  public static void main(String[] args) {
    SpringApplication.run(SignerApplication.class, args);
  }
}
