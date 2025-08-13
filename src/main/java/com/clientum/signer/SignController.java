package com.clientum.signer;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.security.KeyStore;
import java.util.Base64;
import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import eu.europa.esig.dss.validation.CommonCertificateVerifier;

@RestController
@RequestMapping("/xades")
public class SignController {

  public record SignRequest(
      String xmlBase64,           // XML a firmar (base64)
      String p12Base64,           // P12 (base64)
      String password,            // contraseña del P12
      // Política EPES:
      String policyId,            // ej: "urn:oid:2.16.724.1.3.1.1.2.1.9"
      String policyUrl,           // URL info política
      String policyDigestAlg,     // "SHA256" / "SHA512"...
      String policyHashBase64     // hash de la política en base64
  ) {}

  public record SignResponse(String signedXmlBase64) {}

  @PostMapping(
      path = "/epes",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public SignResponse signEpes(@RequestBody SignRequest req) throws Exception {

    // 1) Documento a firmar (enveloped)
    byte[] xmlBytes = Base64.getDecoder().decode(req.xmlBase64());
    DSSDocument document = new InMemoryDocument(xmlBytes, "document.xml");

    // 2) Token PKCS#12 (nota: PasswordProtection en DSS 6.x)
    byte[] p12 = Base64.getDecoder().decode(req.p12Base64());
    KeyStore.PasswordProtection prot =
        new KeyStore.PasswordProtection((req.password() == null ? "" : req.password()).toCharArray());

    DSSPrivateKeyEntry entry;
    try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(p12, prot)) {
      List<DSSPrivateKeyEntry> keys = token.getKeys();
      if (keys == null || keys.isEmpty()) {
        throw new IllegalStateException("El P12 no contiene clave de firma");
      }
      entry = keys.get(0);

      // 3) Parámetros XAdES (EPES = Baseline B + Policy)
      XAdESSignatureParameters params = new XAdESSignatureParameters();
      params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
      params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
      params.setSigningCertificate(entry.getCertificate());
      params.setCertificateChain(entry.getCertificateChain());

      // Política EPES en DSS 6.x -> Policy + bLevel.setSignaturePolicy(...)
      if (req.policyId() != null && !req.policyId().isBlank()
          && req.policyDigestAlg() != null && !req.policyDigestAlg().isBlank()
          && req.policyHashBase64() != null && !req.policyHashBase64().isBlank()) {

        Policy policy = new Policy();
        policy.setId(req.policyId());
        if (req.policyUrl() != null && !req.policyUrl().isBlank()) {
          policy.setSpuri(req.policyUrl());
        }
        DigestAlgorithm da = DigestAlgorithm.forName(req.policyDigestAlg());
        policy.setDigestAlgorithm(da);
        policy.setDigestValue(Base64.getDecoder().decode(req.policyHashBase64()));

        params.bLevel().setSignaturePolicy(policy);
      }

      // 4) Servicio XAdES con verificador (requerido por DSS)
      CommonCertificateVerifier verifier = new CommonCertificateVerifier();
      XAdESService service = new XAdESService(verifier);

      // 5) Flujo de firma DSS
      ToBeSigned toBeSigned = service.getDataToSign(document, params);
      SignatureValue signatureValue =
          token.sign(toBeSigned, params.getDigestAlgorithm(), entry);

      DSSDocument signed = service.signDocument(document, params, signatureValue);

      return new SignResponse(Base64.getEncoder().encodeToString(signed.openStream().readAllBytes()));
    }
  }

  @GetMapping("/health")
  public String health() {
    return "OK";
  }
}
