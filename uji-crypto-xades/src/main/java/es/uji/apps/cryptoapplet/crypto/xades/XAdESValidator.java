package es.uji.apps.cryptoapplet.crypto.xades;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import net.java.xades.security.xml.SignatureStatus;
import net.java.xades.security.xml.ValidateResult;
import net.java.xades.security.xml.XAdES.XAdES;
import net.java.xades.security.xml.XAdES.XAdES_BES;
import net.java.xades.security.xml.XAdES.XMLAdvancedSignature;

import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import es.uji.apps.cryptoapplet.crypto.ValidationResult;

public class XAdESValidator
{
    public ValidationResult verify(byte[] signedData) throws ParserConfigurationException,
            SAXException, IOException, GeneralSecurityException
    {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Element element = db.parse(new ByteArrayInputStream(signedData)).getDocumentElement();

        XAdES_BES xades = (XAdES_BES) XAdES.newInstance(XAdES.BES, element);

        XMLAdvancedSignature fileXML = XMLAdvancedSignature.newInstance(xades);
        List<SignatureStatus> st = fileXML.validate();

        ValidationResult verificationDetails = new ValidationResult();
        verificationDetails.setValid(true);

        for (SignatureStatus status : st)
        {
            if (status.getValidateResult() != ValidateResult.VALID)
            {
                verificationDetails.setValid(false);
                verificationDetails.addError("Sign validation error: " + status.getReasonsAsText());
            }
        }

        return verificationDetails;
    }
}
