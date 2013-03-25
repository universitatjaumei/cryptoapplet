package es.uji.apps.cryptoapplet.crypto.xades;

import es.uji.apps.cryptoapplet.crypto.exceptions.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.exceptions.ValidationException;
import es.uji.apps.cryptoapplet.crypto.signature.validate.AbstractSignatureValidator;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidationOptions;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidationResult;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidator;
import net.java.xades.security.xml.SignatureStatus;
import net.java.xades.security.xml.ValidateResult;
import net.java.xades.security.xml.XAdES.XAdES;
import net.java.xades.security.xml.XAdES.XAdES_BES;
import net.java.xades.security.xml.XAdES.XMLAdvancedSignature;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.List;

public class XAdESSignatureValidator extends AbstractSignatureValidator implements SignatureValidator
{
    public XAdESSignatureValidator(X509Certificate certificate, Provider provider)
            throws CertificateNotFoundException
    {
        super(certificate, provider);
    }

    @Override
    public SignatureValidationResult validate(SignatureValidationOptions signatureValidationOptions)
            throws ValidationException
    {
        try
        {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Element element = db.parse(signatureValidationOptions.getSignedData()).getDocumentElement();

            XAdES_BES xades = (XAdES_BES) XAdES.newInstance(XAdES.BES, element);

            XMLAdvancedSignature fileXML = XMLAdvancedSignature.newInstance(xades);
            List<SignatureStatus> st = fileXML.validate();

            for (SignatureStatus status : st)
            {
                if (status.getValidateResult() != ValidateResult.VALID)
                {
                    throw new ValidationException("Sign validation error: "
                            + status.getReasonsAsText());
                }
            }

            return new SignatureValidationResult(true);
        }
        catch (Exception e)
        {
            throw new ValidationException(e);
        }
    }
}