package com.clientum.signer;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SignController {

    @GetMapping("/smoke")
    public Map<String, Object> smoke() {
        return Map.of(
                "status", "ok",
                "service", "clientumsign",
                "ts", Instant.now().toString()
        );
    }

    // Stub para ir probando subida de archivos (aquí luego metemos la firma real)
    @PostMapping(path = "/sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Map<String, Object> signStub(@RequestPart("file") MultipartFile file) throws Exception {
        return Map.of(
                "received", file.getOriginalFilename(),
                "size", file.getSize(),
                "message", "stub: firma aún no implementada"
        );
    }
}
