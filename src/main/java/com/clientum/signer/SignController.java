package com.clientum.signer;

import static spark.Spark.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore.PasswordProtection;
import java.util.Base64;
import java.util.List;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.SignatureValue;

import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;

import eu.europa.esig.dss.validation.CommonCertificateVerifier; // <- aquí
import eu.europa.esig.dss.validation.CertificateVerifier;

import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESService;

public class SignController {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  public static void main(String[] args) {
    port(getPort());

    // Healthcheck
    get("/health", (req, res) -> "OK");

    // Firma XAdES
    post("/xades-epes", (req, res) -> {
      try {
        JsonNode body = MAPPER.readTree(req.body());

        // 1) XML a firmar
        String xmlB64 = body.path("xmlBase64").asText(null);
        String xmlText = body.path("xml").asText(null);
        byte[] xmlBytes;
        if (xmlB64 != null && !xmlB64.isEmpty()) {
          xmlBytes = Base64.getDecoder().decode(xmlB64);
        } else if (xmlText != null) {
          xmlBytes = xmlText.getBytes(StandardCharsets.UTF_8);
        } else {
          halt(400, "Falta xmlBase64 o xml");
          return "";
        }
        DSSDocument toSign = new InMemoryDocument(xmlBytes, "factura.xml");

        // 2) Certificado
        String p12B64 = body.path("p12Base64").asText();
        String password = body.path("password").asText("");
        if (p12B64 == null || p12B64.isEmpty()) {
          halt(400, "Falta p12Base64");
          return "";
        }
        byte[] p12Bytes = Base64.getDecoder().decode(p12B64);

        try (Pkcs12SignatureToken token =
                 new Pkcs12SignatureToken(
                   new ByteArrayInputStream(p12Bytes),
                   new PasswordProtection(password.toCharArray()))) {

          List<DSSPrivateKeyEntry> keys = token.getKeys();
          if (keys.isEmpty()) {
            halt(400, "El P12 no contiene claves de firma");
            return "";
          }
          DSSPrivateKeyEntry key = keys.get(0);

          // 3) Parámetros XAdES (BES)
          XAdESSignatureParameters params = new XAdESSignatureParameters();
          params.setSigningCertificate(key.getCertificate());
          params.setCertificateChain(key.getCertificateChain());
          params.setDigestAlgorithm(DigestAlgorithm.SHA256);
          // Si luego quieres EPES, aquí se añade la política.

          // 4) Servicio XAdES con verificador
          CertificateVerifier verifier = new CommonCertificateVerifier();
          XAdESService service = new XAdESService(verifier);

          // 5) Firmar
          ToBeSigned dataToSign = service.getDataToSign(toSign, params);
          // ******* orden correcto *******
          SignatureValue sigValue = token.sign(dataToSign, params.getDigestAlgorithm(), key);
          DSSDocument signed = service.signDocument(toSign, params, sigValue);

          String signedB64 = Base64.getEncoder().encodeToString(signed.openStream().readAllBytes());
          res.type("application/json");
          return "{\"xmlFirmadoBase64\":\"" + signedB64 + "\"}";
        }
      } catch (Exception e) {
        res.status(500);
        return "{\"error\":\"" + e.getMessage().replace("\"","'") + "\"}";
      }
    });
  }

  private static int getPort() {
    String p = System.getenv("PORT");
    return (p == null || p.isEmpty()) ? 8080 : Integer.parseInt(p);
  }
}
