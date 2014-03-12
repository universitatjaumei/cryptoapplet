package es.uji.security.crypto.xmldsign;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

import com.sun.org.apache.xerces.internal.dom.DOMOutputImpl;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.config.OS;

public class XMLDsigSignatureFactory implements ISignFormatProvider
{
    static
    {
        AccessController.doPrivileged(new java.security.PrivilegedAction<Void>()
        {
            public Void run()
            {
                if (System.getProperty("java.version").startsWith("1.5"))
                {
                    try
                    {
                        Security.addProvider(new org.jcp.xml.dsig.internal.dom.XMLDSigRI());
                    }
                    catch (Throwable e)
                    {
                        e.printStackTrace();
                    }
                }
                return null;
            }
        });
    }

    public SignatureResult formatSignature(SignatureOptions signatureOptions) throws Exception
    {
        byte[] toSign = OS.inputStreamToByteArray(signatureOptions.getDataToSign());
        X509Certificate cer = signatureOptions.getCertificate();
        PrivateKey pk = signatureOptions.getPrivateKey();

        // We create DOM XMLSigantureFactory
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // XPath filtering for multiple enveloped signatures support
        
        Transform transform = null;
        
        if (signatureOptions.isCoSignEnabled())
        {
            transform = fac.newTransform(Transform.XPATH, new XPathFilterParameterSpec(
                "not(ancestor-or-self::dsig:Signature)", Collections.singletonMap("dsig",
                        XMLSignature.XMLNS)));
        }
        else
        {
            transform = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);            
        }
        
        Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA1, null),
                Collections.singletonList(transform), null, null);

        // Create the SignedInfo.
        SignedInfo si = fac
                .newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null), fac.newSignatureMethod(
                        SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<Object>();
        x509Content.add(cer.getSubjectX500Principal().getName());
        x509Content.add(cer);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(toSign));

        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element.
        DOMSignContext dsc = new DOMSignContext(pk, doc.getDocumentElement());

        // Create the XMLSignature, but don't sign it yet.
        XMLSignature signature = fac.newXMLSignature(si, ki, null, "first", null);

        // Marshal, generate, and sign the enveloped signature.
        signature.sign(dsc);

        // Output the resulting document.
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
//        TransformerFactory tf = TransformerFactory.newInstance();
//        Transformer trans = tf.newTransformer();
//        trans.transform(new DOMSource(doc), new StreamResult(bos));

        DOMImplementationLS domImplLS = (DOMImplementationLS) doc.getImplementation();
        LSSerializer serializer = domImplLS.createLSSerializer();
        serializer.getDomConfig().setParameter("namespaces", false);

        DOMOutputImpl output = new DOMOutputImpl();
        output.setCharacterStream(new PrintWriter(bos));

        serializer.write(doc, output);
        
        SignatureResult signatureResult = new SignatureResult();
        signatureResult.setValid(true);
        signatureResult.setSignatureData(new ByteArrayInputStream(bos.toByteArray()));

        return signatureResult;
    }
}