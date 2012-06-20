package es.uji.apps.cryptoapplet.crypto.xmlsignature.odf;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xml.sax.SAXException;

import es.uji.apps.cryptoapplet.crypto.ValidationResult;

public class ODFValidatorTest
{
    public static void main(String[] args) throws FileNotFoundException, IOException,
            ParserConfigurationException, SAXException, MarshalException, XMLSignatureException
    {
        ODFValidator odtVerifier = new ODFValidator();

        for (String fileName : new String[] { "src/main/resources/signed-cryptoapplet.odt" })
        {
            System.out.println("Verifying " + fileName);

            ValidationResult verificationResult = odtVerifier.verify(new FileInputStream(fileName),
                    new BouncyCastleProvider());

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
