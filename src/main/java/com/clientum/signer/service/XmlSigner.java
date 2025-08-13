package com.clientum.signer.service;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
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

/**
 * Firmado XMLDSig enveloped con SHA256withRSA (Santuario).
 * - signXml(String): usa el keystore global si está configurado (opcional).
 * - signXmlWithP12(String, byte[], String): multiusuario, p12 por petición.
 */
@Service
public class XmlSigner {

  static {
    // Inicializa Santuario una sola vez
    try { Init.init(); } catch (Throwable ignored) {}
  }

  @Autowired(required = false)
  private KeyStore.PrivateKeyEntry signerKeyEntry; // opcional (global)

  public String signXml(String xml) throws Exception {
    if (signerKeyEntry == null) {
      throw new IllegalStateException("No hay keystore global configurado. Usa signXmlWithP12 enviando p12Base64 y p12Password.");
    }
    return signXmlWithKey(xml, signerKeyEntry);
  }

  public String signXmlWithP12(String xml, byte[] p12Bytes, String password) throws Exception {
    char[] sp = password == null ? new char[0] : password.toCharArray();
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(new ByteArrayInputStream(p12Bytes), sp);

    // Alias efectivo
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

    // Crear firma enveloped RSA-SHA256
    XMLSignature signature = new XMLSignature(doc, "",
        XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);

    Element root = doc.getDocumentElement();
    root.appendChild(signature.getElement());

    Transforms transforms = new Transforms(doc);
    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
    transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
    signature.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA256);

    X509Certificate cert = (X509Certificate) entry.getCertificate();
    if (cert != null) {
      signature.addKeyInfo(cert);
      signature.addKeyInfo(cert.getPublicKey());
    }

    PrivateKey privateKey = entry.getPrivateKey();
    signature.sign(privateKey);

    // Serializar
    Transformer tf = TransformerFactory.newInstance().newTransformer();
    tf.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
    tf.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
    tf.setOutputProperty(OutputKeys.INDENT, "no");
    StringWriter sw = new StringWriter();
    tf.transform(new DOMSource(doc), new StreamResult(sw));
    return sw.toString();
  }

  /** Utilidad: devuelve Base64 de un XML. */
  public static String toBase64(String xml) {
    return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
  }

  /** Utilidad: obtiene texto desde base64 si viene así. */
  public static String fromMaybeBase64(String rawOrB64) {
    try {
      byte[] decoded = Base64.getDecoder().decode(rawOrB64);
      String s = new String(decoded, StandardCharsets.UTF_8);
      // heurística: si al decodificar parece XML, lo devolvemos
      if (s.trim().startsWith("<")) return s;
    } catch (IllegalArgumentException ignored) {}
    return rawOrB64;
  }
}

