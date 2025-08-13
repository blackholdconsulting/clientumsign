package com.clientum.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.signature.XAdESSignatureParameters;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.util.List;

@RestController
@RequestMapping("/api")
public class SignController {

    @PostMapping(value = "/sign-xades", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> signXAdES(
            @RequestPart("file") MultipartFile file,
            @RequestPart("p12") MultipartFile p12,
            @RequestPart("password") String password
    ) throws Exception {

        // Documento a firmar (ajusta el MimeTypeEnum si no es PDF)
        byte[] fileBytes = file.getBytes();
        String fileName = file.getOriginalFilename() != null ? file.getOriginalFilename() : "document";
        DSSDocument toSign = new InMemoryDocument(fileBytes, fileName, MimeTypeEnum.PDF);

        // Token PKCS#12 con PasswordProtection (NO char[])
        KeyStore.PasswordProtection pp =
                new KeyStore.PasswordProtection(password.toCharArray());

        SignatureValue signatureValue;
        DSSDocument signedDoc;

        try (Pkcs12SignatureToken token =
                     new Pkcs12SignatureToken(new ByteArrayInputStream(p12.getBytes()), pp)) {

            // Selecciona la primera entrada privada
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new IllegalStateException("El .p12 no contiene claves privadas.");
            }
            DSSPrivateKeyEntry entry = keys.get(0);

            // Parámetros XAdES
            XAdESSignatureParameters params = new XAdESSignatureParameters();
            params.setDigestAlgorithm(DigestAlgorithm.SHA256);
            params.setSignaturePackaging(SignaturePackaging.DETACHED); // ajusta si quieres ENVELOPED/ENVELOPING
            params.setSigningCertificate(entry.getCertificate());
            params.setCertificateChain(entry.getCertificateChain());

            // Servicio de firma
            CertificateVerifier verifier = new CommonCertificateVerifier();
            XAdESService service = new XAdESService(verifier);

            // Flujo de firma correcto
            ToBeSigned dataToSign = service.getDataToSign(toSign, params);
            signatureValue = token.sign(dataToSign, params.getDigestAlgorithm(), entry);
            signedDoc = service.signDocument(toSign, params, signatureValue);
        }

        byte[] out = signedDoc.openStream().readAllBytes();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_XML);
        headers.setContentDispositionFormData("attachment", fileName + ".xades.xml");

        return ResponseEntity.ok()
                .headers(headers)
                .body(out);
    }
}
