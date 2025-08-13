package com.clientum.signer;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// DSS (módulos que SÍ están en Maven Central con 6.3)
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

import java.nio.charset.StandardCharsets;

@RestController
public class SignController {

    @GetMapping(value = "/api/smoke", produces = MediaType.TEXT_PLAIN_VALUE)
    public String smoke() {
        // Solo usamos clases seguras (presentes en dss-document y dss-validation)
        byte[] xml = "<root/>".getBytes(StandardCharsets.UTF_8);
        InMemoryDocument doc = new InMemoryDocument(xml);
        doc.setName("doc.xml");

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        // Si llegamos aquí, DSS está en el classpath y enlaza bien.
        return "DSS OK - doc: " + doc.getName();
    }
}
