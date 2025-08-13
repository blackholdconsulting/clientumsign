package com.clientum.signer.service;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;

@Service
public class XmlSigner {

  static {
    try { Init.init(); } catch (Throwable ignored) {}
  }

  @Autowired(required = false)
  private KeyStore.PrivateKeyEntry signerKeyEntry; // keystore global opcional

  /** Usa keystore global si está configurado. */
  public String signXml(String xml) throws Exception {
    if (signerKeyEntry == null) {
      throw new IllegalStateException("No hay keystore global configurado. Usa signXmlWithP12 enviando p12Base64 y p12Password.");
    }
    return signXmlWithKey(xml, signerKeyEntry);
  }

  /** Multiusuario: firma con el .p12 que llega por petición. */
  public String signXmlWithP12(String xml, byte[] p12Bytes, String password) throws Exception {
    char[] sp = password == null ? new char[0] : password.toCharArray();
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(new ByteArrayInputStream(p12Bytes), sp);

    String alias = null;
    for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
      String a = e.nextElement();
      if (ks.isKeyEntry(a)) { alias = a; break; }
      if (alias == null) alias = a;
    }
    if (alias == null) throw new IllegalStateException("El PKCS12 no contiene alias");

    PrivateKey pk = (PrivateKey) ks.getKey(alias, sp);
    Certificate[] chain = ks.getCertificateChain(alias);
    if ((chain == null || chain.length == 0) && ks.getCertificate(alias) != null) {
      chain = new Certificate[]{ ks.getCertificate(alias) };
    }

    KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(pk, chain);
    return signXmlWithKey(xml, entry);
  }

  private String signXmlWithKey(String xml, KeyStore.PrivateKeyEntry entry) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder()
        .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

    XMLSignature signature = new XMLSignature(doc, "",
        XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);

    Element root = doc.getDocumentElement();
    root.appendChild(signature.getElement());

    Transforms transforms = new Transforms(doc);
    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
    signature.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

    X509Certificate cert = (X509Certificate) entry.getCertificate();
    if (cert != null) {
      signature.addKeyInfo(cert);
      signature.addKeyInfo(cert.getPublicKey());
    }

    signature.sign(entry.getPrivateKey());

    Transformer tf = TransformerFactory.newInstance().newTransformer();
    tf.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
    tf.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
    tf.setOutputProperty(OutputKeys.INDENT, "no");
    StringWriter sw = new StringWriter();
    tf.transform(new DOMSource(doc), new StreamResult(sw));
    return sw.toString();
  }

  public static String toBase64(String xml) {
    return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
  }
}
