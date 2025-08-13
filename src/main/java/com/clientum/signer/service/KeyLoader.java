package com.clientum.signer.service;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

@Component
public class KeyLoader {

  private final Environment env;

  public KeyLoader(Environment env) {
    this.env = env;
  }

  // --- Carga multiusuario: .p12 en BASE64 pasado en la petición ---
  public KeyStore.PrivateKeyEntry loadFromBase64(String p12Base64,
                                                 String storePassword,
                                                 String alias,
                                                 String keyPassword) throws Exception {
    byte[] p12 = Base64.getDecoder().decode(p12Base64.replaceAll("\\s", ""));
    return loadFromBytes(p12, storePassword, alias, keyPassword);
  }

  // --- Carga opcional por ENV (no rompe el arranque si no existe) ---
  public Optional<KeyStore.PrivateKeyEntry> loadFromEnvIfPresent() throws Exception {
    String b64 = env.getProperty("SIGN_KEYSTORE_BASE64");
    String path = env.getProperty("SIGN_KEYSTORE_PATH");
    String storePass = env.getProperty("SIGN_KEYSTORE_PASSWORD");
    String alias = env.getProperty("SIGN_KEY_ALIAS");
    String keyPass = Optional.ofNullable(env.getProperty("SIGN_KEY_PASSWORD")).orElse(storePass);

    if (b64 != null && !b64.isBlank()) {
      return Optional.of(loadFromBase64(b64, storePass, alias, keyPass));
    }
    if (path != null && !path.isBlank()) {
      File f = new File(path);
      if (!f.exists()) return Optional.empty();
      try (FileInputStream fis = new FileInputStream(f)) {
        byte[] bytes = fis.readAllBytes();
        return Optional.of(loadFromBytes(bytes, storePass, alias, keyPass));
      }
    }
    return Optional.empty();
  }

  // --- común ---
  private KeyStore.PrivateKeyEntry loadFromBytes(byte[] p12Bytes,
                                                 String storePassword,
                                                 String alias,
                                                 String keyPassword) throws Exception {
    if (storePassword == null) {
      throw new IllegalArgumentException("Falta la contraseña del almacén (p12Password)");
    }
    char[] sp = storePassword.toCharArray();
    char[] kp = (keyPassword != null ? keyPassword : storePassword).toCharArray();

    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(new ByteArrayInputStream(p12Bytes), sp);

    String effectiveAlias = alias;
    if (effectiveAlias == null || !ks.containsAlias(effectiveAlias)) {
      Enumeration<String> aliases = ks.aliases();
      if (!aliases.hasMoreElements()) {
        throw new IllegalStateException("El PKCS12 no contiene alias");
      }
      effectiveAlias = aliases.nextElement();
    }

    PrivateKey pk = (PrivateKey) ks.getKey(effectiveAlias, kp);
    Certificate[] chain = ks.getCertificateChain(effectiveAlias);
    if (chain == null || chain.length == 0) {
      Certificate cert = ks.getCertificate(effectiveAlias);
      if (cert != null) chain = new Certificate[]{cert};
    }
    return new KeyStore.PrivateKeyEntry(pk, chain);
  }
}
