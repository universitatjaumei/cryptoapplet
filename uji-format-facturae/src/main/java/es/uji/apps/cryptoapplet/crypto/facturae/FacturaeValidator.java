package es.uji.apps.cryptoapplet.crypto.facturae;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.xades.XAdESValidator;

public class FacturaeValidator
{
    public ValidationResult verify(byte[] signedData) throws ParserConfigurationException,
            SAXException, IOException, GeneralSecurityException
    {
        XAdESValidator signatureVerifier = new XAdESValidator();
        return signatureVerifier.verify(signedData);
    }
}
