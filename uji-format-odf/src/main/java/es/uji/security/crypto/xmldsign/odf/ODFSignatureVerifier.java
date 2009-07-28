package es.uji.security.crypto.xmldsign.odf;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.AccessController;
import java.security.Provider;
import java.security.Security;

import javax.xml.crypto.Data;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.jcp.xml.dsig.internal.dom.DOMSubTreeData;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.sun.org.apache.xpath.internal.XPathAPI;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.xmldsign.X509KeySelector;

public class ODFSignatureVerifier
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
    
    public VerificationResult verify(InputStream data, Provider provider) throws FileNotFoundException, IOException, ParserConfigurationException, SAXException, MarshalException, XMLSignatureException
    {   
        // Acceso a los ficheros contenidos en el ODF
        final ODFDocument odt = new ODFDocument(data);

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);        
        DocumentBuilder db = dbf.newDocumentBuilder();
        
        // Documento de firmas
        byte[] documentData = odt.getEntry("META-INF/documentsignatures.xml");        
        final Document d = db.parse(new ByteArrayInputStream(documentData));
        
        // Recuperamos el nodo Signature
        NodeList nl = d.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

        // Establecemos el contexto de validacion
        DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(0));
        valContext.setURIDereferencer(new URIDereferencer() {

            public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException
            {                
                Data result = null;
                
                // El elemento es una referencia interna dentro del documento
                if (uriReference.getURI().startsWith("#"))
                {
                    Document document = d;
                    Node node;
                    
                    try
                    {
                        node = XPathAPI.selectSingleNode(document.getDocumentElement(), "//*[@Id='" + uriReference.getURI().substring(1) + "']");
                        result = new DOMSubTreeData(node, true); 
                    }
                    catch (TransformerException e)
                    {
                        throw new URIReferenceException(e.getMessage(), e);
                    }
                }
                // El elemento es un fichero del ODF
                else
                {                    
                    try
                    {
                        byte[] resourceData = odt.getEntry(uriReference.getURI());
                        result = new OctetStreamData(new ByteArrayInputStream(resourceData));
                    }
                    catch (Exception e)
                    {
                        throw new URIReferenceException(e.getMessage(), e);
                    }
                }

                return result; 
            }            
        });
        
        // Validamos la firma
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        
        VerificationResult verificationResult = new VerificationResult();
        
        if (signature.validate(valContext))
        {
            verificationResult.setValid(true);
        }
        else
        {
            verificationResult.setValid(false);
            
            boolean sv = signature.getSignatureValue().validate(valContext);

            if (sv == false) 
            {
                for (Object o : signature.getSignedInfo().getReferences()) 
                {
                    Reference reference  = (Reference) o;
                    
                    boolean refValid = reference.validate(valContext);
                    verificationResult.addError(reference.getURI() + " - validity status: " + refValid);
                }
            }
        }
        
        return verificationResult;
    }
}