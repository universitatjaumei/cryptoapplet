package es.uji.security.crypto.raw.test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.OS;
import es.uji.security.crypto.raw.RawSignatureFactory;
import es.uji.security.crypto.raw.RawSignatureVerifier;

public class RawSignatureTest
{
    public static void main(String[] args) throws Exception
    {        
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);

        // Cargando certificado de aplicacion
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(new FileInputStream("../uji.keystore"), "cryptoapplet".toCharArray());

        // Recuperando clave privada para firmar
        X509Certificate certificate = (X509Certificate) keystore.getCertificate(keystore.aliases().nextElement());
        Key key = keystore.getKey("uji", "cryptoapplet".toCharArray());

        byte[] data = "data to sign".getBytes();

        // Firmando documento
        ISignFormatProvider signFormatProvider = new RawSignatureFactory();

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
        signatureOptions.setCertificate(certificate);
        signatureOptions.setPrivateKey((PrivateKey) key);
        signatureOptions.setProvider(bcp);

        SignatureResult signatureResult =  signFormatProvider.formatSignature(signatureOptions);
        
        byte[] signedData = OS.inputStreamToByteArray(signatureResult.getSignatureData());
        
        RawSignatureVerifier rawSignatureVerifier = new RawSignatureVerifier();
        
        VerificationResult verificationDetails = rawSignatureVerifier.verify(data, signedData, certificate, new BouncyCastleProvider());
        
        if (verificationDetails.isValid())
        {
            System.out.println("OK");
        }
        else
        {
            System.out.println("BAD SIGNATURE");
        }
    }
}