package com.clientum.signer.service;

import org.springframework.stereotype.Service;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
// 👇 Esta es la constante correcta para el digest
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;

/**
 * Firma XML en modo enveloped con RSA-SHA256 y digest SHA-256 (Santuario).
 */
@Service
public class XmlSigner {

    static {
        // Inicializa la librería de Apache Santuario una sola vez
        Init.init();
    }

    /**
     * Firma un XML (texto) usando clave privada + certificado X509.
     * Devuelve el XML firmado (texto).
     */
    public String signEnveloped(String xmlPlain, PrivateKey privateKey, X509Certificate certificate) throws Exception {
        Document doc = parse(xmlPlain);

        // Crea la firma RSA-SHA256
        XMLSignature xmlSignature = new XMLSignature(
                doc,
                "",
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256
        );

        // Inserta el nodo <Signature> como primer hijo del elemento raíz
        Element root = doc.getDocumentElement();
        root.insertBefore(xmlSignature.getElement(), root.getFirstChild());

        // Transforms: enveloped + canonicalización
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);

        // Referencia al documento con digest SHA-256 (👈 cambio principal)
        xmlSignature.addDocument(
                "",
                transforms,
                MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256
        );

        // KeyInfo con el certificado
        KeyInfo keyInfo = new KeyInfo(doc);
        X509Data x509Data = new X509Data(doc);
        x509Data.addCertificate(certificate);
        keyInfo.add(x509Data);
        xmlSignature.appendKeyInfo(keyInfo);
        xmlSignature.addKeyInfo(certificate.getPublicKey());

        // Firma
        xmlSignature.sign(privateKey);

        // Devuelve el XML firmado en texto
        return toString(doc);
    }

    // -------------------- helpers --------------------

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true); // muy importante para XMLDSig
        DocumentBuilder db = dbf.newDocumentBuilder();
        try (ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))) {
            return db.parse(bais);
        }
    }

    private static String toString(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        StringWriter sw = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }
}
