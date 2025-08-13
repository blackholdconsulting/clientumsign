package com.clientum.signer;

import com.clientum.signer.crypto.Pkcs12Utils;
import com.clientum.signer.crypto.XmlSigner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/facturae")
public class FacturaeController {

    @PostMapping(value = "/sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<byte[]> sign(
            @RequestParam("xml") MultipartFile xml,
            @RequestParam("p12") MultipartFile p12,
            @RequestParam("password") String password
    ) throws Exception {
        var km = Pkcs12Utils.load(p12.getBytes(), password.toCharArray());
        byte[] signed = XmlSigner.signEnveloped(xml.getBytes(), km.privateKey, km.certificate);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=facturae-signed.xml")
                .contentType(MediaType.APPLICATION_XML)
                .body(signed);
    }
}
