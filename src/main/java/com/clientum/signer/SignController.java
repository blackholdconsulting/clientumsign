package com.clientum.signer;

import com.clientum.signer.service.XmlSigner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sign")
public class SignController {

    private final XmlSigner signer;

    @Autowired
    public SignController(XmlSigner signer) {
        this.signer = signer;
    }

    @PostMapping(value = "/xml", consumes = "application/xml", produces = "application/xml")
    public ResponseEntity<String> signXml(@RequestBody String xml) throws Exception {
        String signed = signer.signXml(xml);
        return ResponseEntity.ok(signed);
    }

    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK");
    }
}
