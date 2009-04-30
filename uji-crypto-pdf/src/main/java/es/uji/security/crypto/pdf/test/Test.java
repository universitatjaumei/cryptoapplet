package es.uji.security.crypto.pdf.test;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.pdf.PDFSignatureFactory;

public class Test
{
    public static byte[] inputStreamToByteArray(InputStream in) throws IOException
    {
        byte[] buffer = new byte[2048];
        int length = 0;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        while ((length = in.read(buffer)) >= 0)
        {
            baos.write(buffer, 0, length);
        }

        return baos.toByteArray();
    }

    public static void main(String[] args) throws Exception
    {
        BouncyCastleProvider bcp = new BouncyCastleProvider();
        Security.addProvider(bcp);

        // Cargando certificado de aplicación
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("src/main/resources/test.p12"), "aaa".toCharArray());

        // Recuperando clave privada para firmar
        Certificate cert = ks.getCertificate("aaa");
        PrivateKey privKey = (PrivateKey) ks.getKey("aaa", "aaa".toCharArray());

        byte[] data = inputStreamToByteArray(new FileInputStream("in.pdf"));

        // Firmando documento
        PDFSignatureFactory xsf = new PDFSignatureFactory();

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setToSignByteArray(data);
        signatureOptions.setCertificate((X509Certificate) cert);
        signatureOptions.setPrivateKey(privKey);
        signatureOptions.setProvider(new BouncyCastleProvider());

        byte[] signedData = xsf.formatSignature(signatureOptions);

        FileOutputStream fos = new FileOutputStream("out.pdf");
        fos.write(signedData);
        fos.flush();
        fos.close();
    }
}