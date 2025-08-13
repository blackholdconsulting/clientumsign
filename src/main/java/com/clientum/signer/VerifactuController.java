package com.clientum.signer;

import com.clientum.signer.verifactu.VerifactuService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/verifactu")
public class VerifactuController {

    private final VerifactuService service = new VerifactuService();

    @PostMapping("/rf")
    public ResponseEntity<Map<String,Object>> registro(@RequestBody Map<String,Object> factura) {
        var rr = service.generarRegistro(factura);
        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "numero", rr.numero,
                "huella", rr.huella,
                "encadenado", rr.encadenado
        ));
    }

    @PostMapping("/qr")
    public ResponseEntity<Map<String,String>> qr(@RequestBody Map<String,Object> factura) {
        var rr = service.generarRegistro(factura); // genera y avanza la cadena
        String csv = service.generarQrCsv(factura, rr);
        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "numero", String.valueOf(rr.numero),
                "qr_csv", csv
        ));
    }
}
