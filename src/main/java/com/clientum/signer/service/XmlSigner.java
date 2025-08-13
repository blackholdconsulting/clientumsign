package com.clientum.signer.service;

import org.springframework.stereotype.Service;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;

/**
 * Firma XML (enveloped) usando Apache Santuario,
 * algoritmo RSA-SHA256 y digest SHA-256.
 *
 * Variables de entorno:
 *  - SIGN_P12_BASE64    (obligatoria) PKCS#12 en Base64
 *  - SIGN_P12_PASSWORD  (opcional)   password del keystore
 *  - SIGN_KEY_ALIAS     (opcional)   alias; si falta, coge el primero
 *  - SIGN_KEY_PASSWORD  (opcional)   si falta, usa SIGN_P12_PASSWORD
 */
@Service
public class XmlSigner {

    static {
        // Inicializa la librería una única vez
        Init.init();
    }

    /** Atajo: firma tomando la clave/certificado de variables de entorno. */
    public String signXml(String xmlPlain) throws Exception {
        String p12b64 = System.getenv("SIGN_P12_BASE64");
        if (p12b64 == null || p12b64.isEmpty()) {
            throw new IllegalStateException("SIGN_P12_BASE64 no está definida.");
        }

        String ksPassword = System.getenv("SIGN_P12_PASSWORD");
        char[] ksPwd = ksPassword != null ? ksPassword.toCharArray() : new char[0];

        String keyAlias = System.getenv("SIGN_KEY_ALIAS");
        String keyPassword = System.getenv("SIGN_KEY_PASSWORD");
        char[] keyPwd = keyPassword != null ? keyPassword.toCharArray() : ksPwd;

        // Carga el PKCS#12
        byte[] p12Bytes = Base64.getDecoder().decode(p12b64);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12Bytes), ksPwd);

        // Alias
        if (keyAlias == null || keyAlias.isEmpty()) {
            Enumeration<String> aliases = ks.aliases();
            if (!aliases.hasMoreElements()) {
                throw new IllegalStateException("El PKCS#12 no contiene alias.");
            }
            keyAlias = aliases.nextElement();
        }

        Key key = ks.getKey(keyAlias, keyPwd);
        if (!(key instanceof PrivateKey)) {
            throw new IllegalStateException("No se pudo obtener la clave privada para el alias: " + keyAlias);
        }

        X509Certificate cert = (X509Certificate) ks.getCertificate(keyAlias);
        if (cert == null) {
            throw new IllegalStateException("No se encontró el certificado para el alias: " + keyAlias);
        }

        return signEnveloped(xmlPlain, (PrivateKey) key, cert);
    }

    /** Firma enveloped usando la clave privada y certificado dados. */
    public String signEnveloped(String xmlPlain, PrivateKey privateKey, X509Certificate certificate) throws Exception {
        Document doc = parse(xmlPlain);

        // Crea la firma RSA-SHA256
        XMLSignature xmlSignature = new XMLSignature(
                doc,
                "",
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256
        );

        // Inserta <Signature> como primer hijo del root
        Element root = doc.getDocumentElement();
        root.insertBefore(xmlSignature.getElement(), root.getFirstChild());

        // Transforms: enveloped + canonicalización
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        // Referencia al documento con digest SHA-256
        xmlSignature.addDocument(
                "",
                transforms,
                MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256
        );

        // KeyInfo: en esta versión se añaden vía helpers del propio XMLSignature
        xmlSignature.addKeyInfo(certificate);
        xmlSignature.addKeyInfo(certificate.getPublicKey());

        // Firma con la clave privada
        xmlSignature.sign(privateKey);

        // XML a String
        return toString(doc);
    }

    // -------------------- helpers --------------------

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true); // imprescindible para XMLDSig
        DocumentBuilder db = dbf.newDocumentBuilder();
        try (ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))) {
            return db.parse(bais);
        }
    }

    private static String toString(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        StringWriter sw = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }
}
