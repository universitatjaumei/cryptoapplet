package es.uji.security.crypto.openxades.test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.VerificationDetails;
import es.uji.security.crypto.openxades.OpenXAdESSignatureFactory;
import es.uji.security.crypto.openxades.OpenXAdESSignatureVerifier;
import es.uji.security.util.OS;

public class Test
{
    public static void main(String[] args) throws Exception
    {
    	String pwd= args[0];
    	
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);

        // Cargando certificado de aplicaci�n
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("/home/paul/tmp/mio.p12"), pwd.toCharArray());

        // Recuperando clave privada para firmar
        Certificate certificate = keystore.getCertificate(keystore.aliases().nextElement());
        Key key = keystore.getKey(keystore.aliases().nextElement(), pwd.toCharArray());

        byte[] data = "<root />".getBytes();

        // Firmando documento
        ISignFormatProvider signFormatProvider = new OpenXAdESSignatureFactory();

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setToSignInputstream(new ByteArrayInputStream(data));
        signatureOptions.setCertificate((X509Certificate) certificate);
        signatureOptions.setPrivateKey((PrivateKey) key);
        signatureOptions.setProvider(bcp);

        byte[] signedData = OS.inputStreamToByteArray(signFormatProvider.formatSignature(signatureOptions));
        
        OS.dumpToFile("/tmp/signed-output.xml", signedData);
        
        OpenXAdESSignatureVerifier verifier = new OpenXAdESSignatureVerifier();

        VerificationDetails verificationDetails = verifier.verify(OS.inputStreamToByteArray(new FileInputStream("/tmp/signed-output.xml")));

        
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
