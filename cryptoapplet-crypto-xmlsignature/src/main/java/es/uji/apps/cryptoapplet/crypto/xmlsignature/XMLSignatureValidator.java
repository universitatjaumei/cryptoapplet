package es.uji.apps.cryptoapplet.crypto.xmlsignature;

import java.security.Provider;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import es.uji.apps.cryptoapplet.crypto.BaseValidator;
import es.uji.apps.cryptoapplet.crypto.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.ValidationException;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;

public class XMLSignatureValidator extends BaseValidator implements Validator
{
    public XMLSignatureValidator(X509Certificate certificate, Provider provider)
            throws CertificateNotFoundException
    {
        super(certificate, provider);
    }

    public ValidationResult validate(ValidationOptions validationOptions)
            throws ValidationException
    {
        try
        {
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            // Instantiate the document to be signed.
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(validationOptions.getSignedData());

            // Find Signature element.
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

            if (nl.getLength() == 0)
            {
                throw new SAXException("Cannot find Signature element");
            }

            // Create a DOMValidateContext and specify a KeySelector
            // and document context.

            ValidationResult result = new ValidationResult();

            for (int i = 0; i < nl.getLength(); i++)
            {
                DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(),
                        nl.item(i));

                // Unmarshal the XMLSignature.
                XMLSignature signature = fac.unmarshalXMLSignature(valContext);

                // Validate the XMLSignature.
                boolean coreValidity = signature.validate(valContext);
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

                    break;
                }
            }

            return result;
        }
        catch (Exception e)
        {
            throw new ValidationException(e);
        }
    }
}
