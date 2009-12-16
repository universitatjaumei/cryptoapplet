package es.uji.security.crypto.openxades.test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.openxades.OpenXAdESSignatureFactory;
import es.uji.security.crypto.openxades.OpenXAdESSignatureVerifier;
import es.uji.security.util.OS;

public class TestOpenXAdESSignatureFactory
{
    public static void main(String[] args) throws Exception
    {
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);
        Logger.getRootLogger().setLevel(Level.OFF);
        
        String pin="";
        	
        // Cargando certificado de aplicaci�n
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("/home/paul/tmp/mio.p12"), pin
                .toCharArray());
        X509Certificate certificate = (X509Certificate) keystore.getCertificate(keystore.aliases().nextElement());
        
        // Recuperando clave privada para firmar
        Key key = keystore.getKey(keystore.aliases().nextElement(), pin.toCharArray());

        byte[] data = "<root />".getBytes();

        // Firmando documento
        ISignFormatProvider signFormatProvider = new OpenXAdESSignatureFactory();

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
        signatureOptions.setCertificate((X509Certificate) certificate);
        signatureOptions.setPrivateKey((PrivateKey) key);
        signatureOptions.setProvider(bcp);

        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);
        
        byte[] signedData = OS.inputStreamToByteArray(signatureResult.getSignatureData());
        
        OS.dumpToFile("src/main/resources/signed-output.xml", signedData);
        
        OpenXAdESSignatureVerifier verifier = new OpenXAdESSignatureVerifier();

        VerificationResult verificationDetails = verifier.verify(OS.inputStreamToByteArray(new FileInputStream("src/main/resources/signed-output.xml")));
        
        if (! verificationDetails.isValid())
        {
            for (String r : verificationDetails.getErrors())
            {
                System.out.println(r);                
            }
        }
        else
        {
            System.out.println("Ok");
        }
    }
}
