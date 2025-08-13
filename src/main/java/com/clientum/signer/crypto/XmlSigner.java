package com.clientum.signer.crypto;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

public class XmlSigner {
    public static byte[] signEnveloped(byte[] xml, PrivateKey privateKey, X509Certificate cert) throws Exception {
        // 1) Parse
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true); // MUY importante
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml));

        // 2) Fabrica de firma
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // 3) Referencia al documento (URI vacía) + transforms: Enveloped + Canonicalization
        Transform envTransform = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
        Transform c14nTransform = fac.newTransform(CanonicalizationMethod.INCLUSIVE, (TransformParameterSpec) null);

        Reference ref = fac.newReference(
                "", // documento entero
                fac.newDigestMethod(DigestMethod.SHA256, null),
                Arrays.asList(envTransform, c14nTransform),
                null,
                null
        );

        // 4) SignedInfo
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
                Collections.singletonList(ref)
        );

        // 5) KeyInfo con el certificado
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509Data = kif.newX509Data(Collections.singletonList((XMLStructure) cert));
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509Data));

        // 6) Contexto y firma (inserta <ds:Signature> en la raíz)
        DOMSignContext dsc = new DOMSignContext(privateKey, (Node) doc.getDocumentElement());
        XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);

        // 7) Serializar
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Transformer t = TransformerFactory.newInstance().newTransformer();
        t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        t.setOutputProperty(OutputKeys.INDENT, "no");
        t.transform(new DOMSource(doc), new StreamResult(out));
        return out.toByteArray();
    }
}
