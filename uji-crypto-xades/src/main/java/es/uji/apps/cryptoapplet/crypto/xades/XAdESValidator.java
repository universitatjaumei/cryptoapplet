package es.uji.apps.cryptoapplet.crypto.xades;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import net.java.xades.security.xml.SignatureStatus;
import net.java.xades.security.xml.ValidateResult;
import net.java.xades.security.xml.XAdES.XAdES;
import net.java.xades.security.xml.XAdES.XAdES_BES;
import net.java.xades.security.xml.XAdES.XMLAdvancedSignature;

import org.w3c.dom.Element;

import es.uji.apps.cryptoapplet.crypto.BaseValidator;
import es.uji.apps.cryptoapplet.crypto.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.ValidationException;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;

public class XAdESValidator extends BaseValidator implements Validator
{
    public XAdESValidator(X509Certificate certificate, Provider provider)
            throws CertificateNotFoundException
    {
        super(certificate, provider);
    }

    @Override
    public ValidationResult validate(ValidationOptions validationOptions)
            throws ValidationException
    {
        try
        {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Element element = db.parse(new ByteArrayInputStream(validationOptions.getSignedData()))
                    .getDocumentElement();

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

            return new ValidationResult(true);
        }
        catch (Exception e)
        {
            throw new ValidationException(e);
        }
    }
}