package com.clientum.signer;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore.PasswordProtection;
import java.util.Base64;
import java.util.List;

@RestController
@RequestMapping("/api")
public class SignController {

    public record SignRequest(
            String p12Base64,
            String password,
            String fileBase64,
            String fileName
    ) {}

    public record SignResponse(
            String signedBase64,
            String mimeType,
            String fileName
    ) {}

    @PostMapping(value = "/xades/sign",
                 consumes = MediaType.APPLICATION_JSON_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> signXades(@RequestBody SignRequest req) {
        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(
                new ByteArrayInputStream(Base64.getDecoder().decode(req.p12Base64())),
                new PasswordProtection(req.password().toCharArray())
        )) {
            // Documento a firmar (usar MimeType correcto; p.ej. PDF si tu archivo lo es)
            byte[] data = Base64.getDecoder().decode(req.fileBase64());
            String originalName = (req.fileName() == null || req.fileName().isBlank())
                    ? "input.bin" : req.fileName();

            // Si sabes que es PDF, pon MimeType.PDF; si no, BIN
            MimeType mt = originalName.toLowerCase().endsWith(".pdf") ? MimeType.PDF : MimeType.BINARY;
            DSSDocument toSign = new InMemoryDocument(data, originalName, mt);

            // Tomamos la primera clave del .p12
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(msg("El P12 no contiene claves utilizables."));
            }
            DSSPrivateKeyEntry keyEntry = keys.get(0);

            // Parámetros XAdES (baseline B, SHA-256, Enveloping)
            XAdESSignatureParameters params = new XAdESSignatureParameters();
            params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            params.setDigestAlgorithm(DigestAlgorithm.SHA256);
            params.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            params.setSigningCertificate(keyEntry.getCertificate());
            params.setCertificateChain(keyEntry.getCertificateChain());

            // Servicio + firma
            XAdESService service = new XAdESService(new CommonCertificateVerifier());
            ToBeSigned toBeSigned = service.getDataToSign(toSign, params);

            // ¡OJO al orden correcto de parámetros!
            SignatureValue signatureValue = token.sign(toBeSigned, params.getDigestAlgorithm(), keyEntry);

            DSSDocument signed = service.signDocument(toSign, params, signatureValue);

            byte[] signedBytes = signed.openStream().readAllBytes();
            String outName = originalName + ".xades.xml";

            return ResponseEntity.ok(
                    new SignResponse(Base64.getEncoder().encodeToString(signedBytes),
                            "application/xml", outName)
            );
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(msg("Error firmando: " + e.getMessage()));
        }
    }

    private static String msg(String text) {
        return "{\"message\":\"" + text.replace("\"","\\\"") + "\"}";
    }

    // Endpoint sencillo para comprobar despliegue
    @GetMapping("/health")
    public String health() {
        return "OK";
    }
}
