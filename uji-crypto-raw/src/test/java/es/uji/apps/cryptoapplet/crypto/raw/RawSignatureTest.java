package es.uji.apps.cryptoapplet.crypto.raw;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class RawSignatureTest
{
    @Test
    public void raw() throws Exception
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

        byte[] data = "data to sign".getBytes();

        // Firmando documento
        Formatter signFormatProvider = new RawFormatter();

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
        signatureOptions.setCertificate(certificate);
        signatureOptions.setPrivateKey((PrivateKey) key);
        signatureOptions.setProvider(bcp);

        SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

        byte[] signedData = StreamUtils.inputStreamToByteArray(signatureResult.getSignatureData());

        RawValidator rawSignatureVerifier = new RawValidator();

        ValidationResult verificationDetails = rawSignatureVerifier.verify(data, signedData,
                certificate, new BouncyCastleProvider());

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