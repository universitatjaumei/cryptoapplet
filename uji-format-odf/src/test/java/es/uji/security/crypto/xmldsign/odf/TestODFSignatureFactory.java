package es.uji.security.crypto.xmldsign.odf;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.FileSystemUtils;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;

public class TestODFSignatureFactory
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

        ODFSignatureFactory odfSignatureFactory = new ODFSignatureFactory();
        SignatureResult signatureResult = odfSignatureFactory.formatSignature(signatureOptions);

        if (signatureResult.isValid())
        {
            FileSystemUtils.dumpToFile(new File("src/main/resources/signed-cryptoapplet.odt"),
                    signatureResult.getSignatureData());

            signatureOptions = new SignatureOptions();
            signatureOptions.setDataToSign(new FileInputStream(
                    "src/main/resources/signed-cryptoapplet.odt"));
            signatureOptions.setCertificate(certificate);
            signatureOptions.setPrivateKey((PrivateKey) key);
            signatureOptions.setProvider(bcp);

            odfSignatureFactory = new ODFSignatureFactory();
            signatureResult = odfSignatureFactory.formatSignature(signatureOptions);

            if (signatureResult.isValid())
            {
                FileSystemUtils.dumpToFile(new File("src/main/resources/signed2-cryptoapplet.odt"),
                        signatureResult.getSignatureData());
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