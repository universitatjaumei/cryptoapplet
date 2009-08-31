package es.uji.security.crypto.jxades.test;

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
import es.uji.security.crypto.jxades.JXAdESSignatureFactory;
import es.uji.security.crypto.jxades.JXAdESSignatureVerifier;
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
        signatureOptions.setDataToSign(new FileInputStream("src/main/resources/in.xml"));
        signatureOptions.setCertificate(certificate);
        signatureOptions.setPrivateKey((PrivateKey) key);
        signatureOptions.setProvider(bcp);
        
        JXAdESSignatureFactory jxSignatureFactory = new JXAdESSignatureFactory();
        SignatureResult signatureResult = jxSignatureFactory.formatSignature(signatureOptions);
        
        if (signatureResult.isValid())
        {
            OS.dumpToFile(new File("src/main/resources/out1.xml"), signatureResult.getSignatureData());
            
            signatureOptions = new SignatureOptions();
            signatureOptions.setDataToSign(new FileInputStream("src/main/resources/out1.xml"));
            signatureOptions.setCertificate(certificate);
            signatureOptions.setPrivateKey((PrivateKey) key);
            signatureOptions.setProvider(bcp);
            
            jxSignatureFactory = new JXAdESSignatureFactory();
            signatureResult = jxSignatureFactory.formatSignature(signatureOptions);
            
            if (signatureResult.isValid())
            {
                OS.dumpToFile(new File("src/main/resources/out2.xml"), signatureResult.getSignatureData());
            }
            else
            {
                for (String error : signatureResult.getErrors())
                {
                    System.out.println(error);
                }
            }            
        }
        else
        {
            for (String error : signatureResult.getErrors())
            {
                System.out.println(error);
            }
        }        
    }
}
