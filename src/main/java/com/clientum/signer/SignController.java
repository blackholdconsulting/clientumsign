package com.clientum.signer;

import com.clientum.signer.service.XmlSigner;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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

    @GetMapping("/smoke")
    public Map<String, Object> smoke() {
        return Map.of(
                "status", "ok",
                "service", "clientumsign",
                "ts", java.time.Instant.now().toString()
        );
    }

    // JSON: { "xml": "<Facturae ...>...</Facturae>" }
    @PostMapping(value = "/sign/xml", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> signXmlJson(@RequestBody Map<String, String> body) throws Exception {
        String xml = body.getOrDefault("xml", "");
        if (xml.isBlank()) return ResponseEntity.badRequest().body(Map.of("error", "Falta campo 'xml'"));
        String signed = signer.signXml(xml);
        String b64 = Base64.getEncoder().encodeToString(signed.getBytes(StandardCharsets.UTF_8));
        return ResponseEntity.ok(Map.of("signedXmlBase64", b64));
    }

    // Alias “específicos” (delegan en /sign/xml). Mismo contrato de entrada.
    @PostMapping(value = "/sign/facturae", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> signFacturae(@RequestBody Map<String, String> body) throws Exception {
        return signXmlJson(body);
    }

    @PostMapping(value = "/sign/verifactu", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> signVerifactu(@RequestBody Map<String, String> body) throws Exception {
        return signXmlJson(body);
    }
}
