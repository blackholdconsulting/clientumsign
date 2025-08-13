package com.clientum.signer.service;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
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
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Service
public class XmlSigner {

    private final PrivateKey privateKey;
    private final X509Certificate certificate;

    static {
        // inicializa apache xmlsec una sola vez
        Init.init();
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
    }

    public XmlSigner(KeyStore.PrivateKeyEntry entry) {
        this.privateKey   = entry.getPrivateKey();
        this.certificate  = (X509Certificate) entry.getCertificate();
    }

    public String signXml(String xml) throws Exception {
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        return signXml(bytes);
    }

    public String signXml(byte[] xmlBytes) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xmlBytes));

        // Firma RSA-SHA256, C14N sin comentarios
        XMLSignature sig = new XMLSignature(
                doc,
                "",
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
                Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS
        );

        Element root = doc.getDocumentElement();
        root.appendChild(sig.getElement());

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA256);

        sig.addKeyInfo(certificate);
        sig.addKeyInfo(certificate.getPublicKey());

        PrivateKey pk = this.privateKey;
        sig.sign(pk);

        // Serializa
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer t = tf.newTransformer();
        t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        t.setOutputProperty(OutputKeys.INDENT, "no");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        t.transform(new DOMSource(doc), new StreamResult(out));
        return out.toString(StandardCharsets.UTF_8);
    }
}
