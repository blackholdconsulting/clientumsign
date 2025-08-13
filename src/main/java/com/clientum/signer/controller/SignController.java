package com.clientum.signer.controller;

import com.clientum.signer.api.dto.SignXmlRequest;
import com.clientum.signer.api.dto.SignXmlResponse;
import com.clientum.signer.service.KeyLoader;
import com.clientum.signer.service.XmlSigner;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import java.util.Base64;

@RestController
@RequestMapping("/api")
public class SignController {

  private final XmlSigner xmlSigner;
  private final KeyLoader keyLoader;

  public SignController(XmlSigner xmlSigner, KeyLoader keyLoader) {
    this.xmlSigner = xmlSigner;
    this.keyLoader = keyLoader;
  }

  @GetMapping("/smoke")
  public ResponseEntity<?> smoke() {
    return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(
      "{\"status\":\"ok\",\"service\":\"clientumsign\"}"
    );
  }

  @GetMapping("/sign/health")
  public String health() {
    return "OK";
  }

  @PostMapping(value = "/sign/xml", consumes = MediaType.APPLICATION_JSON_VALUE,
                                  produces = MediaType.APPLICATION_JSON_VALUE)
  public ResponseEntity<?> signXml(@RequestBody SignXmlRequest req) throws Exception {
    String xml = null;
    if (req.getXml() != null && !req.getXml().isBlank()) {
      xml = req.getXml();
    } else if (req.getXmlBase64() != null && !req.getXmlBase64().isBlank()) {
      byte[] xmlBytes = Base64.getDecoder().decode(req.getXmlBase64().replaceAll("\\s", ""));
      xml = new String(xmlBytes, StandardCharsets.UTF_8);
    }
    if (xml == null || xml.isBlank()) {
      return ResponseEntity.badRequest().body("{\"error\":\"Falta xml o xmlBase64\"}");
    }

    KeyStore.PrivateKeyEntry entry;
    if (req.getP12Base64() != null && !req.getP12Base64().isBlank()) {
      if (req.getP12Password() == null) {
        return ResponseEntity.badRequest().body("{\"error\":\"Falta p12Password\"}");
      }
      entry = keyLoader.loadFromBase64(req.getP12Base64(), req.getP12Password(),
                                       req.getAlias(), req.getKeyPassword());
    } else {
      // modo “global” opcional por ENV (no falla si no está)
      var opt = keyLoader.loadFromEnvIfPresent();
      if (opt.isEmpty()) {
        return ResponseEntity.badRequest().body("{\"error\":\"Falta p12Base64 o keystore global por ENV\"}");
      }
      entry = opt.get();
    }

    String signedXml = xmlSigner.signXmlWithKey(xml, entry);
    String b64 = Base64.getEncoder().encodeToString(signedXml.getBytes(StandardCharsets.UTF_8));
    return ResponseEntity.ok(new SignXmlResponse(b64));
  }
}
