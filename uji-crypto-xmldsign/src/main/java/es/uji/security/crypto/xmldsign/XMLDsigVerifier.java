package es.uji.security.crypto.xmldsign;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.AccessController;
import java.security.Security;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import es.uji.security.crypto.VerificationResult;

public class XMLDsigVerifier
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
    
    public VerificationResult verify(byte[] signedData) throws SAXException, IOException, ParserConfigurationException, MarshalException, XMLSignatureException
    {
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(signedData));

        // Find Signature element.
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

        if (nl.getLength() == 0)
        {
            throw new SAXException("Cannot find Signature element");
        }

        // Create a DOMValidateContext and specify a KeySelector
        // and document context.
        DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(0));

        // Unmarshal the XMLSignature.
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        // Validate the XMLSignature.
        boolean coreValidity = signature.validate(valContext);

        VerificationResult result = new VerificationResult();
        result.setValid(coreValidity);
        
        // Check core validation status.
        if (coreValidity == false)
        {
            boolean sv = signature.getSignatureValue().validate(valContext);
            result.addError("signature validation status: " + sv);
            
            if (sv == false)
            {
                // Check the validation status of each Reference.
                for (Object o : signature.getSignedInfo().getReferences())
                {
                    Reference r = (Reference) o;
                    
                    boolean refValid = r.validate(valContext);
                    result.addError("ref[" + r.getURI() + "] validity status: " + refValid);
                }
            }
        }
        
        return result;
    }
}
