package com.clientum.signer.controller;

import com.clientum.signer.api.dto.SignXmlResponse;
import com.clientum.signer.service.XmlSigner;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SignController {

  private final XmlSigner signer;

  public SignController(XmlSigner signer) {
    this.signer = signer;
  }

  /**
   * Firma un XML:
   * Body JSON admite:
   *  - xml          (texto)   | o xmlBase64
   *  - p12Base64    (opcional, multiusuario)
   *  - p12Password  (opcional, multiusuario)
   * Si no se envía p12Base64 se intentará usar el keystore global (si existe).
   */
  @PostMapping(value = "/sign/xml", consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  public SignXmlResponse signXml(@RequestBody Map<String, String> body) throws Exception {
    String xml = body.get("xml");
    String xmlB64 = body.get("xmlBase64");
    if (xml == null && xmlB64 == null) {
      throw new IllegalArgumentException("Debes enviar 'xml' o 'xmlBase64'");
    }
    if (xml == null) {
      xml = new String(Base64.getDecoder().decode(xmlB64), StandardCharsets.UTF_8);
    }

    String p12Base64 = body.get("p12Base64");
    String p12Password = body.getOrDefault("p12Password", "");

    String signedXml;
    if (p12Base64 != null && !p12Base64.isBlank()) {
      byte[] p12Bytes = Base64.getDecoder().decode(p12Base64.replaceAll("\\s",""));
      signedXml = signer.signXmlWithP12(xml, p12Bytes, p12Password);
    } else {
      signedXml = signer.signXml(xml); // usa keystore global si existe
    }

    return new SignXmlResponse(
        XmlSigner.toBase64(signedXml),
        "XMLDSig Enveloped SHA256withRSA"
    );
  }
}

