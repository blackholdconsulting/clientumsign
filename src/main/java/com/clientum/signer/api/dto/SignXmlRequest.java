package com.clientum.signer.api.dto;

public class SignXmlRequest {
  // XML a firmar: manda uno de los dos
  private String xml;         // plano (string)
  private String xmlBase64;   // o base64

  // Material criptográfico del usuario (requerido en modo multiusuario)
  private String p12Base64;     // PKCS#12 en base64 (una sola línea)
  private String p12Password;   // password del almacén

  // Opcionales
  private String alias;         // si hay varios alias en el .p12
  private String keyPassword;   // si la clave tiene pass distinta al almacén

  // getters/setters
  public String getXml() { return xml; }
  public void setXml(String xml) { this.xml = xml; }

  public String getXmlBase64() { return xmlBase64; }
  public void setXmlBase64(String xmlBase64) { this.xmlBase64 = xmlBase64; }

  public String getP12Base64() { return p12Base64; }
  public void setP12Base64(String p12Base64) { this.p12Base64 = p12Base64; }

  public String getP12Password() { return p12Password; }
  public void setP12Password(String p12Password) { this.p12Password = p12Password; }

  public String getAlias() { return alias; }
  public void setAlias(String alias) { this.alias = alias; }

  public String getKeyPassword() { return keyPassword; }
  public void setKeyPassword(String keyPassword) { this.keyPassword = keyPassword; }
}
