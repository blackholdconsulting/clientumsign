package com.clientum.signer.dto;

public class SignRequest {
  // XML del documento: puede ser Base64 o texto plano
  public String xml;

  // Certificado P12 en Base64
  public String p12;

  // Password del P12
  public String password;

  // --- Política (opcional para EPES; si no se manda, firma Baseline-B sin política) ---
  // OID o URL de la política, ej: "2.16.724.1.3.1.1.2.1.9"
  public String policyId;

  // Hash de la política en Base64 (del binario del documento de política)
  public String policyHashBase64;

  // Algoritmo del hash de la política (por defecto SHA256)
  public String policyDigestAlgorithm;

  // Envoltorio y nivel (opcionales)
  // "ENVELOPED" (defecto) | "ENVELOPING" | "DETACHED"
  public String packaging;
  // "XAdES_BASELINE_B" (defecto). Puedes elevarlo si luego añades TSA, etc.
  public String level;
}
