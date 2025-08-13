package com.clientum.signer.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Enumeration;

@Configuration
public class KeyConfig {

  /**
   * Bean OPCIONAL: solo se crea si hay un keystore global configurado por ENV.
   * Así el servicio arranca sin problemas en modo multiusuario (p12 por petición).
   */
  @Bean
  @ConditionalOnExpression("('${SIGN_KEYSTORE_BASE64:}' != '') or ('${SIGN_KEYSTORE_PATH:}' != '')")
  public KeyStore.PrivateKeyEntry signerKeyEntry(
      @Value("${SIGN_KEYSTORE_BASE64:}") String ksBase64,
      @Value("${SIGN_KEYSTORE_PATH:}")  String ksPath,
      @Value("${SIGN_KEYSTORE_PASSWORD:}") String storePassword,
      @Value("${SIGN_KEY_ALIAS:}") String alias,
      @Value("${SIGN_KEY_PASSWORD:}") String keyPassword
  ) throws Exception {

    if (storePassword == null || storePassword.isBlank()) {
      throw new IllegalStateException("Falta SIGN_KEYSTORE_PASSWORD para el keystore global");
    }

    char[] sp = storePassword.toCharArray();
    char[] kp = (keyPassword != null && !keyPassword.isBlank())
        ? keyPassword.toCharArray() : sp;

    KeyStore ks = KeyStore.getInstance("PKCS12");

    if (ksBase64 != null && !ksBase64.isBlank()) {
      byte[] bytes = Base64.getDecoder().decode(ksBase64.replaceAll("\\s", ""));
      ks.load(new ByteArrayInputStream(bytes), sp);
    } else {
      File f = new File(ksPath);
      try (FileInputStream fis = new FileInputStream(f)) {
        ks.load(fis, sp);
      }
    }

    String effectiveAlias = alias;
    if (effectiveAlias == null || effectiveAlias.isBlank() || !ks.containsAlias(effectiveAlias)) {
      Enumeration<String> aliases = ks.aliases();
      if (!aliases.hasMoreElements()) {
        throw new IllegalStateException("El PKCS12 no contiene alias");
      }
      effectiveAlias = aliases.nextElement();
    }

    PrivateKey pk = (PrivateKey) ks.getKey(effectiveAlias, kp);
    Certificate[] chain = ks.getCertificateChain(effectiveAlias);
    if (chain == null || chain.length == 0) {
      Certificate c = ks.getCertificate(effectiveAlias);
      if (c != null) chain = new Certificate[]{c};
    }

    return new KeyStore.PrivateKeyEntry(pk, chain);
  }
}
