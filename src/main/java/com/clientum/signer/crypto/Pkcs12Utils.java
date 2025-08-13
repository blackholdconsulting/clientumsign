package com.clientum.signer.crypto;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class Pkcs12Utils {

    public static class KeyMaterial {
        public final PrivateKey privateKey;
        public final X509Certificate certificate;

        public KeyMaterial(PrivateKey pk, X509Certificate cert) {
            this.privateKey = pk;
            this.certificate = cert;
        }
    }

    public static KeyMaterial load(byte[] p12Bytes, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12Bytes), password);

        String alias = null;
        Enumeration<String> e = ks.aliases();
        while (e.hasMoreElements()) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) { alias = a; break; }
        }
        if (alias == null) throw new IllegalStateException("No hay entrada de clave en el .p12");

        PrivateKey pk = (PrivateKey) ks.getKey(alias, password);
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        return new KeyMaterial(pk, cert);
    }
}
