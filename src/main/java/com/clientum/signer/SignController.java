package com.clientum.signer;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

import org.w3c.dom.Document;

@RestController
public class SignController {

    @GetMapping("/")
    public String home() {
        return """
            <h2>✅ clientumsign en marcha</h2>
            <p>Endpoints útiles:</p>
            <ul>
              <li><a href="/api/smoke">/api/smoke</a> — prueba rápida</li>
              <li><a href="/health">/health</a> — estado</li>
            </ul>
            """;
    }

    @GetMapping("/api/smoke")
    public Map<String, Object> smoke() {
        return Map.of(
            "status", "ok",
            "ts", new Date().toInstant().toString(),
            "service", "clientumsign"
        );
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "UP");
    }

    /**
     * Firma XML (enveloped) con un .p12 (PKCS#12) y contraseña.
     * Curl de ejemplo:
     * curl -X POST https://TU_HOST/api/sign/xml \
     *   -F "xml=@/ruta/ejemplo.xml" \
     *   -F "p12=@/ruta/certificado.p12" \
     *   -F "password=tu_pass" -o signed.xml
     */
    @PostMapping(value = "/api/sign/xml", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> signXml(
            @RequestParam("xml") MultipartFile xmlFile,
            @RequestParam("p12") MultipartFile p12File,
            @RequestParam("password") String password
    ) throws Exception {

        // --- Cargar KeyStore PKCS#12 ---
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(p12File.getBytes()), password.toCharArray());

        String alias = Collections.list(ks.aliases()).stream()
                .filter(a -> {
                    try { return ks.isKeyEntry(a); } catch (Exception e) { return false; }
                })
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No se encontró clave en el .p12"));

        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);

        // --- Parsear XML (namespace-aware y seguro) ---
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        // Endurecer parser
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xmlFile.getBytes()));

        // --- Construir firma XMLDSig (enveloped, RSA-SHA256) ---
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA256, null);
        Transform enveloped = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
        Transform c14n = fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null);

        Reference ref = fac.newReference(
                "", // documento completo
                dm,
                List.of(enveloped, c14n),
                null,
                null
        );

        CanonicalizationMethod cm = fac.newCanonicalizationMethod(
                CanonicalizationMethod.EXCLUSIVE,
                (C14NMethodParameterSpec) null
        );

        SignatureMethod sm = fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null);
        SignedInfo si = fac.newSignedInfo(cm, sm, List.of(ref));

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509Data = kif.newX509Data(List.of(cert));
        KeyInfo ki = kif.newKeyInfo(List.of(x509Data));

        DOMSignContext signContext = new DOMSignContext(privateKey, doc.getDocumentElement());
        XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(signContext);

        // --- Serializar resultado ---
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer trans = tf.newTransformer();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        trans.transform(new DOMSource(doc), new StreamResult(baos));
        byte[] out = baos.toByteArray();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"signed.xml\"")
                .contentType(MediaType.APPLICATION_XML)
                .body(out);
    }
}
