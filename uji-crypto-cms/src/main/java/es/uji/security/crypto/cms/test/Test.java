package es.uji.security.crypto.cms.test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.cms.CMSSignatureFactory;
import es.uji.security.crypto.cms.CMSSignatureVerifier;
import es.uji.security.util.OS;

public class Test
{
    public static void main(String[] args) throws Exception
    {
        if (Security.getProvider("BC") == null)
        {
            BouncyCastleProvider bcp = new BouncyCastleProvider();
            Security.addProvider(bcp);
        }
        
        // Cargando certificado de aplicacion
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream("../uji.keystore"), "cryptoapplet".toCharArray());
        
        // Recuperando clave privada para firmar
        X509Certificate certificate = (X509Certificate) ks.getCertificate("uji");
        PrivateKey privateKey = (PrivateKey) ks.getKey("uji", "cryptoapplet".toCharArray());
        
        byte[] data = "data to sign".getBytes();
        
        ISignFormatProvider signFormatProvider = new CMSSignatureFactory();
        
        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
        signatureOptions.setCertificate(certificate);
        signatureOptions.setPrivateKey(privateKey);
        signatureOptions.setProvider(new BouncyCastleProvider());
        
        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);
        
        byte[] signedData = OS.inputStreamToByteArray(signatureResult.getSignatureData());
        
        CMSSignatureVerifier signatureVerifier = new CMSSignatureVerifier();
                
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate caCertificate = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream("../uji-config/src/main/resources/ujica.pem"));
        
        X509Certificate[] caCertificates = new X509Certificate[] { };
        if (signatureVerifier.verify(data, signedData, caCertificates, new BouncyCastleProvider()))
        {
            System.out.println("OK");
        }
        else
        {
            System.out.println("BAD SIGNATURE");
        }
    }
}
