package com.clientum.signer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Base64;
import java.util.Enumeration;

@Configuration
public class KeyConfig {

    @Bean
    public PrivateKeyEntry signerKeyEntry() throws Exception {
        String ksB64 = System.getenv("SIGN_KEYSTORE_BASE64"); // recomendado en Render
        String ksPath = System.getenv("SIGN_KEYSTORE_PATH");   // alternativa: ruta a .p12
        String ksPass = envOrDefault("SIGN_KEYSTORE_PASSWORD", "changeit");
        String keyPass = envOrDefault("SIGN_KEY_PASSWORD", ksPass);
        String aliasEnv = System.getenv("SIGN_KEY_ALIAS"); // opcional

        KeyStore ks = KeyStore.getInstance("PKCS12");

        if (ksB64 != null && !ksB64.isBlank()) {
            byte[] bytes = Base64.getMimeDecoder().decode(ksB64.getBytes(StandardCharsets.UTF_8));
            ks.load(new ByteArrayInputStream(bytes), ksPass.toCharArray());
        } else if (ksPath != null && !ksPath.isBlank()) {
            try (FileInputStream fis = new FileInputStream(ksPath)) {
                ks.load(fis, ksPass.toCharArray());
            }
        } else {
            throw new IllegalStateException("Debe definir SIGN_KEYSTORE_BASE64 o SIGN_KEYSTORE_PATH");
        }

        String alias = aliasEnv;
        if (alias == null || alias.isBlank()) {
            alias = firstPrivateKeyAlias(ks);
            if (alias == null) throw new IllegalStateException("No se encontró alias con clave privada en el keystore");
        }

        KeyStore.ProtectionParameter prot = new KeyStore.PasswordProtection(keyPass.toCharArray());
        KeyStore.Entry entry = ks.getEntry(alias, prot);
        if (!(entry instanceof PrivateKeyEntry pke)) {
            throw new IllegalStateException("El alias '" + alias + "' no contiene una clave privada");
        }
        return pke;
    }

    private static String firstPrivateKeyAlias(KeyStore ks) throws Exception {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (ks.isKeyEntry(a)) return a;
        }
        return null;
    }

    private static String envOrDefault(String k, String def) {
        String v = System.getenv(k);
        return (v == null || v.isBlank()) ? def : v;
        }
}
