package com.clientum.signer.service;

import org.springframework.stereotype.Service;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class XmlSigner {

  public String signXmlWithKey(String xml, KeyStore.PrivateKeyEntry entry) throws Exception {
    Document doc = parseXml(xml);

    PrivateKey privateKey = entry.getPrivateKey();

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

    // Referencia al documento entero con Transform ENVELOPED
    Reference ref = fac.newReference(
        "",
        fac.newDigestMethod(DigestMethod.SHA256, null),
        Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
        null,
        null
    );

    // SignedInfo: Canonicalización + RSA-SHA256
    SignedInfo si = fac.newSignedInfo(
        fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
        fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
        Collections.singletonList(ref)
    );

    // KeyInfo con el certificado del usuario
    KeyInfoFactory kif = fac.getKeyInfoFactory();
    List<Object> x509Content = new ArrayList<>();
    if (entry.getCertificate() instanceof X509Certificate x509) {
      x509Content.add(x509.getSubjectX500Principal().getName());
      x509Content.add(x509);
    }
    // Añade el resto de la cadena si existe
    if (entry.getCertificateChain() != null) {
      for (var c : entry.getCertificateChain()) {
        if (c instanceof X509Certificate x) x509Content.add(x);
      }
    }
    X509Data xd = kif.newX509Data(x509Content);
    KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

    // Firmar
    DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());
    XMLSignature signature = fac.newXMLSignature(si, ki);
    signature.sign(dsc);

    return toString(doc);
  }

  private static Document parseXml(String xml) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    return dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
  }

  private static String toString(Document doc) throws Exception {
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer t = tf.newTransformer();
    StringWriter sw = new StringWriter();
    t.transform(new DOMSource(doc), new StreamResult(sw));
    return sw.toString();
  }
}
