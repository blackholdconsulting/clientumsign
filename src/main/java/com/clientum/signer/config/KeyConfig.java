package com.clientum.signer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Base64;

@Configuration
public class KeyConfig {

  /** Solo crea el bean si hay keystore por env; si no, NO crashea. */
  @Bean
  @Conditional(SignerKeyEntryCondition.class)
  public KeyStore.PrivateKeyEntry signerKeyEntry(Environment env) throws Exception {
    String b64 = env.getProperty("SIGN_KEYSTORE_BASE64");
    String path = env.getProperty("SIGN_KEYSTORE_PATH");
    String pwd  = env.getProperty("SIGN_KEYSTORE_PASSWORD", "");

    char[] pass = pwd.toCharArray();
    KeyStore ks = KeyStore.getInstance("PKCS12");

    if (b64 != null && !b64.isBlank()) {
      byte[] bytes = Base64.getDecoder().decode(b64);
      try (InputStream in = new java.io.ByteArrayInputStream(bytes)) {
        ks.load(in, pass);
      }
    } else {
      try (InputStream in = new FileInputStream(path)) {
        ks.load(in, pass);
      }
    }

    String alias = ks.aliases().nextElement();
    KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)
        ks.getEntry(alias, new KeyStore.PasswordProtection(pass));
    return entry;
  }

  /** Condición: hay SIGN_KEYSTORE_BASE64 o SIGN_KEYSTORE_PATH. */
  public static class SignerKeyEntryCondition implements Condition {
    @Override
    public boolean matches(ConditionContext ctx, AnnotatedTypeMetadata md) {
      Environment env = ctx.getEnvironment();
      String b64 = env.getProperty("SIGN_KEYSTORE_BASE64");
      String path = env.getProperty("SIGN_KEYSTORE_PATH");
      return (b64 != null && !b64.isBlank()) || (path != null && !path.isBlank());
    }
  }
}
