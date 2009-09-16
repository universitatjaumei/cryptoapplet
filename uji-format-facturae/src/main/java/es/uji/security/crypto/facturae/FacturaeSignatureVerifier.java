package es.uji.security.crypto.facturae;

import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.jxades.JXAdESSignatureVerifier;

public class FacturaeSignatureVerifier
{
    public VerificationResult verify(byte[] signedData) throws ParserConfigurationException,
            SAXException, IOException
    {
        JXAdESSignatureVerifier signatureVerifier = new JXAdESSignatureVerifier();
        return signatureVerifier.verify(signedData);
    }
}
