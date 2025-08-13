package com.clientum.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

/**
 * POST /xades-epes
 * Body JSON:
 * {
 *   "xml": "<Facturae ...>...</Facturae>",
 *   "p12": "BASE64_P12",
 *   "password": "claveP12",
 *   // opcionales (para EPES Facturae 3.1):
 *   "policyId": "urn:facturae:policies:facturae-3-1",
 *   "policyUrl": "https://www.facturae.gob.es/Politica_de_firma/Politica_de_firma_v3_1.pdf",
 *   "policyHashBase64": "BASE64_DEL_HASH_DE_LA_POLITICA",
 *   "policyDigest": "SHA256"
 * }
 */
@RestController
public class SignController {

  public record SignRequest(
      String xml,
      String p12,
      String password,
      String policy,           // alias opcional (no se usa si pasas los 4 campos de política)
      String policyId,
      String policyUrl,
      String policyHashBase64,
      String policyDigest
  ) {}

  @GetMapping("/health")
  public String health() { return "OK"; }

  @PostMapping(
      value = "/xades-epes",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_XML_VALUE
  )
  public @ResponseBody byte[] sign(@RequestBody SignRequest req) throws Exception {
    if (req.xml() == null || req.xml().isBlank())
      throw new IllegalArgumentException("xml es obligatorio");
    if (req.p12() == null || req.p12().isBlank())
      throw new IllegalArgumentException("p12 es obligatorio (Base64)");
    if (req.password() == null)
      throw new IllegalArgumentException("password es obligatorio");

    byte[] xmlBytes = req.xml().getBytes(StandardCharsets.UTF_8);
    byte[] p12Bytes = Base64.getDecoder().decode(req.p12());

    try (Pkcs12SignatureToken token =
             new Pkcs12SignatureToken(new ByteArrayInputStream(p12Bytes), req.password().toCharArray())) {

      List<DSSPrivateKeyEntry> keys = token.getKeys();
      if (keys.isEmpty()) throw new IllegalStateException("No se encontró clave en el P12");
      DSSPrivateKeyEntry entry = keys.get(0);

      // Documento a firmar
      DSSDocument document = new InMemoryDocument(xmlBytes, "facturae.xml");

      // Parámetros XAdES
      XAdESSignatureParameters params = new XAdESSignatureParameters();
      params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);     // nivel base
      params.setSignaturePackaging(SignaturePackaging.ENVELOPED);    // firma embebida en el XML
      params.setDigestAlgorithm(DigestAlgorithm.SHA256);
      params.setSigningCertificate(entry.getCertificate());
      params.setCertificateChain(entry.getCertificateChain());

      // ---- EPES (política explícita) ----
      // Si te pasan los 4 campos de política (Id/URL/hashBase64/digest) los aplicamos.
      if (notBlank(req.policyId()) && notBlank(req.policyUrl())
          && notBlank(req.policyHashBase64()) && notBlank(req.policyDigest())) {

        var bLevel = params.bLevel();
        bLevel.setSignaturePolicyId(req.policyId());
        bLevel.setSignaturePolicyDescription("Facturae policy");
        bLevel.setSignaturePolicyQualifier(req.policyUrl());
        bLevel.setSignaturePolicyDigestAlgorithm(DigestAlgorithm.forName(req.policyDigest()));
        bLevel.setSignaturePolicyHash(Base64.getDecoder().decode(req.policyHashBase64()));
      }
      // Si NO se pasan, firmará como XAdES-B. Para FACe, envía la política correcta desde tu backend.

      // Servicio y flujo de firma
      CommonCertificateVerifier verifier = new CommonCertificateVerifier();
      XAdESService service = new XAdESService(verifier);

      ToBeSigned toBeSigned = service.getDataToSign(document, params);
      SignatureValue signatureValue = token.sign(toBeSigned, params.getDigestAlgorithm(), entry);
      DSSDocument signed = service.signDocument(document, params, signatureValue);

      return signed.openStream().readAllBytes();
    }
  }

  private static boolean notBlank(String s) { return s != null && !s.isBlank(); }
}
