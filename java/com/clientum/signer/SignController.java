package com.clientum.signer;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
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
import java.util.Map;

@RestController
public class SignController {

  record SignRequest(String xml, String p12, String password,
                     String policy,        // opcional: "facturae-3.1-epes"
                     String policyId,      // opcional: id de política (si no usas el alias)
                     String policyUrl,     // opcional: URL de política
                     String policyHashBase64, // opcional: hash de la política (Base64)
                     String policyDigest   // opcional: "SHA256", etc.
  ) {}

  @PostMapping(value = "/xades-epes", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_XML_VALUE)
  public @ResponseBody byte[] sign(@RequestBody SignRequest req) throws Exception {
    if (req.xml() == null || req.p12() == null || req.password() == null) {
      throw new IllegalArgumentException("xml, p12 y password son obligatorios");
    }

    byte[] xmlBytes = req.xml().getBytes(StandardCharsets.UTF_8);
    byte[] p12Bytes = Base64.getDecoder().decode(req.p12());

    // Cargamos el P12 del usuario
    try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(new ByteArrayInputStream(p12Bytes), req.password().toCharArray())) {
      List<DSSPrivateKeyEntry> keys = token.getKeys();
      if (keys.isEmpty()) throw new IllegalStateException("No se encontró clave en el P12");
      DSSPrivateKeyEntry entry = keys.get(0);

      // Documento a firmar
      DSSDocument doc = new InMemoryDocument(xmlBytes, "facturae.xml");

      // Parámetros XAdES-EPES (enveloped)
      XAdESSignatureParameters params = new XAdESSignatureParameters();
      params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B); // base
      params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
      params.setDigestAlgorithm(DigestAlgorithm.SHA256);
      params.setSigningCertificate(entry.getCertificate());
      params.setCertificateChain(entry.getCertificateChain());

      // EPES (política explícita). Dos opciones:
      // (A) Alias "facturae-3.1-epes" -> carga integrada (pon tus valores reales aquí si quieres fijarlos)
      // (B) Pasar policyId/policyUrl/policyHashBase64/policyDigest en la petición
      Map<String, String> facturaePolicy = Map.of(
        "policyId",   "urn:facturae:policies:facturae-3-1", // <- ajusta al identificador corporativo que uséis
        "policyUrl",  "https://www.facturae.gob.es/Politica_de_firma/Politica_de_firma_v3_1.pdf",
        "hashBase64", "RELLENA_HASH_BASE64_DE_LA_POLITICA"   // <-- pon el hash real en Base64 (SHA256)
      );

      String policy = req.policy() != null ? req.policy() : "facturae-3.1-epes";
      String pid = req.policyId();
      String purl = req.policyUrl();
      String phash = req.policyHashBase64();
      String pdig = req.policyDigest();

      if ("facturae-3.1-epes".equalsIgnoreCase(policy)) {
        // usa valores por defecto anteriores si el cliente no manda los suyos
        pid  = (pid  == null || pid.isBlank())  ?  facturaePolicy.get("policyId")   : pid;
        purl = (purl == null || purl.isBlank()) ?  facturaePolicy.get("policyUrl")  : purl;
        phash= (phash== null || phash.isBlank())?  facturaePolicy.get("hashBase64") : phash;
        pdig = (pdig == null || pdig.isBlank()) ? "SHA256" : pdig;
      }

      // Si viene política completa, la añadimos (EPES)
      if (pid != null && purl != null && phash != null && pdig != null) {
        var bLevel = params.bLevel();
        bLevel.setSignaturePolicyId(pid);
        bLevel.setSignaturePolicyDescription("Facturae policy");
        bLevel.setSignaturePolicyQualifier(purl);
        bLevel.setSignaturePolicyDigestAlgorithm(DigestAlgorithm.forName(pdig));
        bLevel.setSignaturePolicyHash(Base64.getDecoder().decode(phash));
      }

      // Verificador de certificados
      CommonCertificateVerifier verifier = new CommonCertificateVerifier();
      verifier.setTrustedCertSources(new CommonCertificateSource()); // ajusta si quieres confiar en raíces

      // Servicio XAdES
      XAdESService service = new XAdESService(verifier);

      // Flujo de firma
      ToBeSigned toBeSigned = service.getDataToSign(doc, params);
      SignatureValue signatureValue = token.sign(toBeSigned, params.getDigestAlgorithm(), entry);
      DSSDocument signed = service.signDocument(doc, params, signatureValue);

      return signed.openStream().readAllBytes();
    }
  }

  @GetMapping("/health")
  public String health() { return "OK"; }
}
