package es.uji.security.crypto.jxades.test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.jxades.JXAdESSignatureVerifier;
import es.uji.security.util.OS;

public class TestJXAdESSignatureVerifier
{
    public static void main(String[] args) throws FileNotFoundException, IOException,
            ParserConfigurationException, SAXException
    {
        JXAdESSignatureVerifier odtVerifier = new JXAdESSignatureVerifier();

        for (String fileName : new String[] { "src/main/resources/out2.xml",
                "src/main/resources/out1.xml" })
        {
            System.out.println("Verifying " + fileName);

            byte[] signedData = OS.inputStreamToByteArray(new FileInputStream(fileName));

            VerificationResult verificationResult = odtVerifier.verify(signedData);

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
