package com.clientum.signer.api.dto;

/**
 * Request para /api/sign/xml
 * Puedes enviar xml (texto) o xmlBase64.
 * Para multiusuario: p12Base64 + p12Password.
 */
public class SignXmlRequest {

  private String xml;
  private String xmlBase64;
  private String p12Base64;
  private String p12Password;

  public SignXmlRequest() { }

  public String getXml() { return xml; }
  public void setXml(String xml) { this.xml = xml; }

  public String getXmlBase64() { return xmlBase64; }
  public void setXmlBase64(String xmlBase64) { this.xmlBase64 = xmlBase64; }

  public String getP12Base64() { return p12Base64; }
  public void setP12Base64(String p12Base64) { this.p12Base64 = p12Base64; }

  public String getP12Password() { return p12Password; }
  public void setP12Password(String p12Password) { this.p12Password = p12Password; }
}
