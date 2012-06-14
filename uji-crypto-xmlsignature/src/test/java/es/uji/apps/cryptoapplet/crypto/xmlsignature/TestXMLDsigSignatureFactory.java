package es.uji.apps.cryptoapplet.crypto.xmlsignature;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.utils.FileSystemUtils;

public class TestXMLDsigSignatureFactory
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

        XMLDsigSignatureFactory xmlSignatureFactory = new XMLDsigSignatureFactory();
        SignatureResult signatureResult = xmlSignatureFactory.format(signatureOptions);

        if (signatureResult.isValid())
        {
            FileSystemUtils.dumpToFile(new File("src/main/resources/out1.xml"),
                    signatureResult.getSignatureData());

            signatureOptions = new SignatureOptions();
            signatureOptions.setDataToSign(new FileInputStream("src/main/resources/out1.xml"));
            signatureOptions.setCertificate(certificate);
            signatureOptions.setPrivateKey((PrivateKey) key);
            signatureOptions.setProvider(bcp);

            xmlSignatureFactory = new XMLDsigSignatureFactory();
            signatureResult = xmlSignatureFactory.format(signatureOptions);

            if (signatureResult.isValid())
            {
                FileSystemUtils.dumpToFile(new File("src/main/resources/out2.xml"),
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
