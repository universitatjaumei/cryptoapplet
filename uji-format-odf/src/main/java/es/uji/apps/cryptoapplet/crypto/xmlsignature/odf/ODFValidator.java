package es.uji.apps.cryptoapplet.crypto.xmlsignature.odf;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.cert.X509Certificate;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerException;

import org.jcp.xml.dsig.internal.dom.DOMSubTreeData;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.sun.org.apache.xpath.internal.XPathAPI;

import es.uji.apps.cryptoapplet.crypto.BaseValidator;
import es.uji.apps.cryptoapplet.crypto.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.ValidationException;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;

public class ODFValidator extends BaseValidator implements Validator
{
    public ODFValidator(X509Certificate certificate, Provider provider)
            throws CertificateNotFoundException
    {
        super(certificate, provider);
    }

    public ValidationResult validate(ValidationOptions validationOptions)
            throws ValidationException
    {
        try
        {
            // Acceso a los ficheros contenidos en el ODF
            final ODFDocument odt = new ODFDocument(validationOptions.getSignedData());

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();

            // Documento de firmas
            byte[] documentData = odt.getEntry("META-INF/documentsignatures.xml");
            final Document d = db.parse(new ByteArrayInputStream(documentData));

            // Recuperamos el nodo Signature
            NodeList nl = d.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

            ValidationResult verificationResult = new ValidationResult();

            // Establecemos el contexto de validacion
            for (int i = 0; i < nl.getLength(); i++)
            {
                DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(),
                        nl.item(i));
                valContext.setURIDereferencer(new URIDereferencer()
                {

                    @SuppressWarnings("restriction")
                    public Data dereference(URIReference uriReference, XMLCryptoContext context)
                            throws URIReferenceException
                    {
                        Data result = null;

                        // El elemento es una referencia interna dentro del documento
                        if (uriReference.getURI().startsWith("#"))
                        {
                            Document document = d;
                            Node node;

                            try
                            {
                                node = XPathAPI.selectSingleNode(document.getDocumentElement(),
                                        "//*[@Id='" + uriReference.getURI().substring(1) + "']");
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
                            Reference reference = (Reference) o;

                            boolean refValid = reference.validate(valContext);
                            verificationResult.addError(reference.getURI() + " - validity status: "
                                    + refValid);
                        }
                    }
                }
            }

            return verificationResult;
        }
        catch (Exception e)
        {
            throw new ValidationException(e);
        }
    }
}