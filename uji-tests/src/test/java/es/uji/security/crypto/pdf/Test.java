package es.uji.security.crypto.pdf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.config.ConfigManager;
import es.uji.security.crypto.config.OS;

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

        // Enable TSA
        ConfigManager conf = ConfigManager.getInstance();
        conf.setProperty("PDFSIG_TIMESTAMPING", "true");
        conf.setProperty("PDFSIG_TSA_URL", "http://tss.accv.es:8318/tsa");

        // Cargando certificado de aplicacion
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(new FileInputStream("../uji.keystore"), "cryptoapplet".toCharArray());

        // Recuperando clave privada para firmar
        Certificate certificate = keystore.getCertificate("uji");
        Key key = keystore.getKey("uji", "cryptoapplet".toCharArray());

        byte[] data = inputStreamToByteArray(new FileInputStream("src/main/resources/in.pdf"));

        // Firmando documento
        PDFSignatureFactory pdfSignatureFactory = new PDFSignatureFactory();

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
        signatureOptions.setCertificate((X509Certificate) certificate);
        signatureOptions.setPrivateKey((PrivateKey) key);
        signatureOptions.setProvider(bcp);

        SignatureResult signatureResult = pdfSignatureFactory.formatSignature(signatureOptions);

        if (signatureResult.getSignatureData() == null)
        {
            List<String> errs = signatureResult.getErrors();
            for (String i : errs)
            {
                System.out.println("Error: " + i);
            }
        }
        else
        {
            byte[] signedData = OS.inputStreamToByteArray(signatureResult.getSignatureData());
            FileOutputStream fos = new FileOutputStream("src/main/resources/out.pdf");
            fos.write(signedData);
            fos.flush();
            fos.close();
        }
    }
}
