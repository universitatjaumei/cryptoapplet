package es.uji.security.crypto.xmldsign.odf.test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xml.sax.SAXException;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.xmldsign.odf.ODFSignatureVerifier;

public class TestVerify
{
    public static void main(String[] args) throws FileNotFoundException, IOException, ParserConfigurationException, SAXException, MarshalException, XMLSignatureException
    {
        ODFSignatureVerifier odtVerifier = new ODFSignatureVerifier();

        for (String fileName : new String[] { "src/main/resources/signed2-cryptoapplet.odt" })
        {
            System.out.println("Verifying " + fileName);

            VerificationResult verificationResult = odtVerifier.verify(
                    new FileInputStream(fileName), new BouncyCastleProvider());

            if (verificationResult.isValid())
            {
                System.out.println("OK");
            }
            else
            {
                System.out.println("ERROR");

                for (String error : verificationResult.getErrors())
                {
                    System.out.println(error);
                }
            }
        }
    }
}
