package com.clientum.signer.api.dto;

public class SignXmlResponse {

  private String signedXmlBase64;
  private String algorithm;
  private long ts;

  public SignXmlResponse() { }

  public SignXmlResponse(String signedXmlBase64, String algorithm) {
    this.signedXmlBase64 = signedXmlBase64;
    this.algorithm = algorithm;
    this.ts = System.currentTimeMillis();
  }

  public String getSignedXmlBase64() { return signedXmlBase64; }
  public void setSignedXmlBase64(String signedXmlBase64) { this.signedXmlBase64 = signedXmlBase64; }

  public String getAlgorithm() { return algorithm; }
  public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

  public long getTs() { return ts; }
  public void setTs(long ts) { this.ts = ts; }
}
