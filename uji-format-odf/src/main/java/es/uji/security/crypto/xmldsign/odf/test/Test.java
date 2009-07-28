package es.uji.security.crypto.xmldsign.odf.test;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.xmldsign.odf.ODFSignatureFactory;
import es.uji.security.crypto.xmldsign.odf.ODFSignatureVerifier;
import es.uji.security.util.OS;

public class Test
{
    public static void main(String[] args) throws Exception
    {
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);

        // Cargando certificado de aplicacion
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(new FileInputStream("../uji.keystore"), "cryptoapplet".toCharArray());

        // Recuperando clave privada para firmar
        X509Certificate certificate = (X509Certificate) keystore.getCertificate(keystore.aliases()
                .nextElement());
        Key key = keystore.getKey("uji", "cryptoapplet".toCharArray());

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setDataToSign(new FileInputStream("src/main/resources/original.odt"));
        signatureOptions.setCertificate(certificate);
        signatureOptions.setPrivateKey((PrivateKey) key);
        signatureOptions.setProvider(bcp);
        
        ODFSignatureFactory aodSigner = new ODFSignatureFactory();
        SignatureResult signatureResult = aodSigner.formatSignature(signatureOptions);
        
        if (signatureResult.isValid())
        {
            OS.dumpToFile(new File("src/main/resources/signed-cryptoapplet.odt"), signatureResult.getSignatureData());
        }
        else
        {
            for (String error : signatureResult.getErrors())
            {
                System.out.println(error);
            }
        }
        
        ODFSignatureVerifier odtVerifier = new ODFSignatureVerifier();
        
        for (String fileName : new String[] { "src/main/resources/signed-openoffice.odt", "src/main/resources/signed-cryptoapplet.odt" })
        {
            System.out.println("Verifying " + fileName);
            
            VerificationResult verificationResult = odtVerifier.verify(new FileInputStream(fileName), bcp);
            
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