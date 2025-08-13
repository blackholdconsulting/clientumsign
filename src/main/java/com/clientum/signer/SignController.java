package com.clientum.signer;

import com.clientum.signer.dto.SignRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Base64;

@RestController
public class SignController {

  @GetMapping("/healthz")
  public ResponseEntity<String> health() {
    return ResponseEntity.ok("ok");
  }

  @PostMapping(value = "/xades-epes", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_XML_VALUE)
  public ResponseEntity<String> sign(@RequestBody SignRequest req) throws Exception {
    if (req == null || isBlank(req.xml) || isBlank(req.p12) || isBlank(req.password)) {
      return ResponseEntity.badRequest().body("<error>xml, p12 y password son obligatorios</error>");
    }

    // 1) Carga documento XML (acepta Base64 o texto plano)
    byte[] xmlBytes = decodeMaybeBase64(req.xml);
    DSSDocument document = new InMemoryDocument(xmlBytes, "input.xml", "application/xml");

    // 2) Prepara parámetros XAdES
    XAdESSignatureParameters params = new XAdESSignatureParameters();
    params.setSignatureLevel(parseLevel(req.level)); // por defecto: BASELINE_B
    params.setSignaturePackaging(parsePackaging(req.packaging)); // por defecto: ENVELOPED
    params.setDigestAlgorithm(parseDigest(req.policyDigestAlgorithm)); // SHA256

    // EPES = Baseline + política explícita
    if (!isBlank(req.policyId) && !isBlank(req.policyHashBase64)) {
      Policy policy = new Policy();
      policy.setId(req.policyId);
      policy.setDigestAlgorithm(parseDigest(req.policyDigestAlgorithm));
      policy.setDigestValue(Base64.getDecoder().decode(req.policyHashBase64));
      params.bLevel().setSignaturePolicy(policy);
    }

    // 3) Verificador y servicio
    CertificateVerifier verifier = new CommonCertificateVerifier();
    XAdESService service = new XAdESService(verifier);

    // 4) Token PKCS#12
    byte[] p12Bytes = Base64.getDecoder().decode(req.p12);
    KeyStore.PasswordProtection prot = new KeyStore.PasswordProtection(req.password.toCharArray());
    try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new ByteArrayInputStream(p12Bytes), prot)) {

      // 5) Datos a firmar
      ToBeSigned dataToSign = service.getDataToSign(document, params);

      // 6) Clave privada (primer alias)
      DSSPrivateKeyEntry key = token.getKeys().get(0);

      // 7) Firma criptográfica
      SignatureValue sigValue = token.sign(dataToSign, params.getDigestAlgorithm(), key);

      // 8) Ensambla firma XAdES
      DSSDocument signed = service.signDocument(document, params, sigValue);

      // 9) Devuelve XML firmado
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      signed.writeTo(baos);
      String xmlSigned = baos.toString(StandardCharsets.UTF_8);
      return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML).body(xmlSigned);
    }
  }

  // -------- Helpers --------
  private static boolean isBlank(String s) { return s == null || s.trim().isEmpty(); }

  private static byte[] decodeMaybeBase64(String s) {
    try {
      return Base64.getDecoder().decode(s);
    } catch (IllegalArgumentException ignored) {
      return s.getBytes(StandardCharsets.UTF_8);
    }
  }

  private static SignatureLevel parseLevel(String level) {
    if ("XAdES_BASELINE_LTA".equalsIgnoreCase(level)) return SignatureLevel.XAdES_BASELINE_LTA;
    if ("XAdES_BASELINE_LT".equalsIgnoreCase(level))  return SignatureLevel.XAdES_BASELINE_LT;
    if ("XAdES_BASELINE_T".equalsIgnoreCase(level))   return SignatureLevel.XAdES_BASELINE_T;
    return SignatureLevel.XAdES_BASELINE_B;
  }

  private static SignaturePackaging parsePackaging(String p) {
    if ("DETACHED".equalsIgnoreCase(p))   return SignaturePackaging.DETACHED;
    if ("ENVELOPING".equalsIgnoreCase(p)) return SignaturePackaging.ENVELOPING;
    return SignaturePackaging.ENVELOPED;
  }

  private static DigestAlgorithm parseDigest(String d) {
    if ("SHA512".equalsIgnoreCase(d)) return DigestAlgorithm.SHA512;
    if ("SHA384".equalsIgnoreCase(d)) return DigestAlgorithm.SHA384;
    if ("SHA1".equalsIgnoreCase(d))   return DigestAlgorithm.SHA1;
    return DigestAlgorithm.SHA256;
  }
}
