package es.uji.security.crypto.openxades.test;

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
import es.uji.security.crypto.openxades.OpenXAdESSignatureFactory;
import es.uji.security.crypto.openxades.OpenXAdESSignatureVerifier;
import es.uji.security.util.OS;

public class Test
{
    public static void main(String[] args) throws Exception
    {
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);

        // Cargando certificado de aplicaci�n
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("/tmp/x.p12"), "here your pwd".toCharArray());

        // Recuperando clave privada para firmar
        Certificate certificate = keystore.getCertificate(keystore.aliases().nextElement());
        Key key = keystore.getKey(keystore.aliases().nextElement(), "here your pwd".toCharArray());

        byte[] data = "<root />".getBytes();

        // Firmando documento
        ISignFormatProvider signFormatProvider = new OpenXAdESSignatureFactory();

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setToSignByteArray(data);
        signatureOptions.setCertificate((X509Certificate) certificate);
        signatureOptions.setPrivateKey((PrivateKey) key);
        signatureOptions.setProvider(bcp);

        byte[] signedData = signFormatProvider.formatSignature(signatureOptions);

        OS.dumpToFile("/tmp/signed-output.xml", signedData);
        
        OpenXAdESSignatureVerifier verifier = new OpenXAdESSignatureVerifier();
        String[] result = verifier.verify(new FileInputStream("/tmp/signed-output.xml"));
        
        if (result != null && result.length > 0)
        {
            for (String r : result)
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
