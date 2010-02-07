package es.uji.security.crypto.mityc.test;

import java.io.FileInputStream;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.config.OS;
import es.uji.security.crypto.mityc.MitycXAdESSignatureValidator;

public class Test
{
    public static void main(String[] args) throws Exception
    {
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);

        byte[] signedData = OS.inputStreamToByteArray(new FileInputStream(
                "src/main/resources/out.xml"));

        MitycXAdESSignatureValidator v = new MitycXAdESSignatureValidator();
        System.out.println((v.verify(signedData)) ? "OK" : "MAL");
    }
}