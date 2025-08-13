package com.clientum.signer.verifactu;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class VerifactuService {

    private final ObjectMapper mapper = new ObjectMapper();
    // Estado por serie-ejercicio (para demo/homologación en memoria)
    private final Map<String, ChainState> chains = new ConcurrentHashMap<>();

    public static class ChainState {
        public long ultimoNumero = 0L;
        public String ultimaHuella = "INIT";
    }

    public static class RegistroResult {
        public final long numero;
        public final String huella;
        public final String encadenado;

        public RegistroResult(long numero, String huella, String encadenado) {
            this.numero = numero;
            this.huella = huella;
            this.encadenado = encadenado;
        }
    }

    private String key(String serie, int ejercicio) {
        return serie + ":" + ejercicio;
    }

    public RegistroResult generarRegistro(Map<String, Object> factura) {
        String serie = String.valueOf(factura.getOrDefault("serie", "A"));
        int ejercicio = (int) factura.getOrDefault("ejercicio", LocalDate.now().getYear());

        ChainState st = chains.computeIfAbsent(key(serie, ejercicio), k -> new ChainState());
        long siguiente = st.ultimoNumero + 1;

        // Campos base (ajusta si tu payload usa otros nombres)
        String emisorNif   = String.valueOf(factura.getOrDefault("emisorNif", ""));
        String receptorNif = String.valueOf(factura.getOrDefault("receptorNif", ""));
        String fecha       = String.valueOf(factura.getOrDefault("fecha", LocalDate.now().toString()));
        String total       = String.valueOf(factura.getOrDefault("total", "0.00"));

        // Cadena canónica simple para la huella (orden estable y sin espacios)
        String canon = String.join("|",
                emisorNif, receptorNif, serie, String.valueOf(siguiente), String.valueOf(ejercicio), fecha, total
        );

        String base = canon + "|" + st.ultimaHuella;
        String huella = sha256b64url(base);
        String encadenado = st.ultimaHuella; // por transparencia devolvemos también la anterior

        // Avanza estado
        st.ultimoNumero = siguiente;
        st.ultimaHuella = huella;

        return new RegistroResult(siguiente, huella, encadenado);
    }

    public String generarQrCsv(Map<String, Object> factura, RegistroResult rr) {
        // Construye una cadena QR/CSV mínima con datos clave + huella
        // Formato libre para demo: VERIFACTU;NIF;SERIE;NUM;EJERCICIO;FECHA;TOTAL;HUELLA
        String serie = String.valueOf(factura.getOrDefault("serie", "A"));
        int ejercicio = (int) factura.getOrDefault("ejercicio", LocalDate.now().getYear());
        String emisorNif   = String.valueOf(factura.getOrDefault("emisorNif", ""));
        String fecha       = String.valueOf(factura.getOrDefault("fecha", LocalDate.now().toString()));
        String total       = String.valueOf(factura.getOrDefault("total", "0.00"));

        return String.join(";",
                "VERIFACTU",
                emisorNif,
                serie,
                String.valueOf(rr.numero),
                String.valueOf(ejercicio),
                fecha,
                total,
                rr.huella
        );
    }

    private static String sha256b64url(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(s.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(dig);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("unused")
    private String toJson(Object o) {
        try {
            return mapper.writeValueAsString(o);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
