package es.uji.security.crypto.xmldsign;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.OS;
import es.uji.security.crypto.xmldsign.XMLDsigVerifier;

public class TestXMLDsigVerifier
{
    public static void main(String[] args) throws FileNotFoundException, IOException, SAXException,
            ParserConfigurationException, MarshalException, XMLSignatureException
    {
        String[] files = new String[] { "src/main/resources/out1.xml",
                "src/main/resources/out2.xml" };

        for (String file : files)
        {
            System.out.println("Verify " + file);

            byte[] signedData = OS.inputStreamToByteArray(new FileInputStream(file));

            XMLDsigVerifier verifier = new XMLDsigVerifier();
            VerificationResult verificationResult = verifier.verify(signedData);

            if (verificationResult.isValid())
            {
                System.out.println("OK");
            }
            else
            {
                System.out.println("MAL");

                for (String error : verificationResult.getErrors())
                {
                    System.out.println(error);
                }
            }
        }
    }
}
