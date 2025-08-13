package com.clientum.signer;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import eu.europa.esig.dss.model.InMemoryDocument;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SignController {

    @GetMapping("/smoke")
    public Map<String, Object> smoke() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");

        // Probar que la librería DSS está presente creando un InMemoryDocument
        try {
            byte[] xml = "<test/>".getBytes(StandardCharsets.UTF_8);
            InMemoryDocument doc = new InMemoryDocument(xml, "test.xml");
            out.put("dss", "ok");
            out.put("docClass", doc.getClass().getName());
        } catch (Throwable t) {
            out.put("dss", "error: " + t.getClass().getSimpleName() + " - " + t.getMessage());
        }

        return out;
    }
}
