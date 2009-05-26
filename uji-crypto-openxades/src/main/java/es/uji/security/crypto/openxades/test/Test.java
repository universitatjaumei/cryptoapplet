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

public class Test
{
    public static void main(String[] args) throws Exception
    {
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);

        // Cargando certificado de aplicación
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream("/mnt/data/oracle/OraHome1/Apache/Apache/recursos-uji/certificados-uji/eujier.p12"), "Heroes2000".toCharArray());

        // Recuperando clave privada para firmar
        Certificate certificate = keystore.getCertificate("eujier");
        Key key = keystore.getKey("eujier", "Heroes2000".toCharArray());

        byte[] data = "<root />".getBytes();

        // Firmando documento
        ISignFormatProvider signFormatProvider = new OpenXAdESSignatureFactory();

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setToSignByteArray(data);
        signatureOptions.setCertificate((X509Certificate) certificate);
        signatureOptions.setPrivateKey((PrivateKey) key);
        signatureOptions.setProvider(bcp);

        byte[] signedData = signFormatProvider.formatSignature(signatureOptions);

        System.out.println(new String(signedData));
    }
}
