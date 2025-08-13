package com.clientum.signer;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// DSS imports mínimos para garantizar compilación
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESService;

import java.nio.charset.StandardCharsets;

@RestController
public class SignController {

    // Endpoint de humo: usa clases de DSS de forma segura para confirmar que compila y enlaza
    @GetMapping(value = "/api/smoke", produces = MediaType.TEXT_PLAIN_VALUE)
    public String smoke() {
        // Documento XML mínimo en memoria
        byte[] xml = "<root/>".getBytes(StandardCharsets.UTF_8);
        DSSDocument doc = new InMemoryDocument(xml, "doc.xml", MimeType.XML);

        // Verificador y servicio XAdES
        CertificateVerifier verifier = new CommonCertificateVerifier();
        XAdESService service = new XAdESService(verifier);

        // Parámetros de firma básicos
        XAdESSignatureParameters params = new XAdESSignatureParameters();
        params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        params.setSignaturePackaging(SignaturePackaging.ENVELOPING);

        // Solo preparamos los bytes a firmar (no firmamos en este demo)
        ToBeSigned tbs = service.getDataToSign(doc, params);

        return "DSS OK - bytes a firmar: " + tbs.getBytes().length;
    }
}
