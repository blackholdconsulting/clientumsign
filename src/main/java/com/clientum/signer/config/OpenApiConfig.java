package com.clientum.signer.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import org.springframework.context.annotation.Configuration;

@OpenAPIDefinition(
    info = @Info(
        title = "Clientum Signer API",
        version = "v1",
        description = "API para firmar XML (Facturae/VeriFactu) con certificados del usuario.",
        contact = @Contact(name = "Clientum"),
        license = @License(name = "Apache-2.0")
    )
)
@Configuration
public class OpenApiConfig {
    // Configuración adicional si la necesitas (grouping, servers, etc.).
}
