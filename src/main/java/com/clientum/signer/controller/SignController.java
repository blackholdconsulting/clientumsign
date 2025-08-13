package com.clientum.signer.controller;

import com.clientum.signer.api.dto.SignXmlRequest;
import com.clientum.signer.api.dto.SignXmlResponse;
import com.clientum.signer.service.XmlSigner;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
@RequestMapping("/api/sign")
public class SignController {

  private final XmlSigner signer;

  public SignController(XmlSigner signer) {
    this.signer = signer;
  }

  @PostMapping("/xml")
  public SignXmlResponse signXml(@RequestBody SignXmlRequest req) {
    try {
      String xml = extractXml(req);
      String signed;

      // Multiusuario: si viene p12 en la petición, se usa ese.
      if (req.getP12Base64() != null && !req.getP12Base64().isBlank()) {
        byte[] p12 = Base64.getDecoder().decode(req.getP12Base64());
        String pwd = req.getP12Password() == null ? "" : req.getP12Password();
        signed = signer.signXmlWithP12(xml, p12, pwd);
      } else {
        // Keystore global (si está configurado). Si no, lanzará una IllegalStateException clara.
        signed = signer.signXml(xml);
      }

      return new SignXmlResponse(
          Base64.getEncoder().encodeToString(signed.getBytes(StandardCharsets.UTF_8)),
          "RSA_SHA256"
      );
    } catch (IllegalStateException ex) {
      // Mapea mensajes claros a 400
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
    } catch (Exception ex) {
      throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No se pudo firmar el XML", ex);
    }
  }

  private String extractXml(SignXmlRequest req) {
    if (req.getXml() != null && !req.getXml().isBlank()) {
      return req.getXml();
    }
    if (req.getXmlBase64() != null && !req.getXmlBase64().isBlank()) {
      return new String(Base64.getDecoder().decode(req.getXmlBase64()), StandardCharsets.UTF_8);
    }
    throw new IllegalStateException("Debes enviar xml (texto) o xmlBase64");
  }
}
