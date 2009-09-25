package es.uji.security.crypto.facturae.test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.facturae.FacturaeSignatureVerifier;
import es.uji.security.util.OS;

public class TestFacturaeVerifier
{
    public static void main(String[] args) throws FileNotFoundException,
            ParserConfigurationException, SAXException, IOException
    {
        FacturaeSignatureVerifier facturaeSignatureVerifier = new FacturaeSignatureVerifier();
        VerificationResult verificationResult = facturaeSignatureVerifier
                .verify(OS.inputStreamToByteArray(new FileInputStream(
                        "src/main/resources/out-facturae.xml")));

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
