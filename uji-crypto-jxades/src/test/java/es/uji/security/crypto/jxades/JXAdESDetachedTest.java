package es.uji.security.crypto.jxades;

import es.uji.security.crypto.BaseCryptoAppletTest;
import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.OS;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

public class JXAdESDetachedTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream("".getBytes()));
        signatureOptions.setEnveloped(false);
        signatureOptions.setCoSignEnabled(false);
        signatureOptions.setDetached(true);
        signatureOptions.addReference("http://www.irs.gov/pub/irs-pdf/fw4.pdf");
    }

    @Test
    public void jxadesDetached() throws Exception
    {
        // Sign

        ISignFormatProvider signFormatProvider = new JXAdESSignatureFactory();
        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);

        showErrors(signatureResult, baseDir + "out-jxades-detached.xml");

        // Verify

        byte[] signedData = OS.inputStreamToByteArray(new FileInputStream(baseDir
                + "out-jxades-detached.xml"));

        JXAdESSignatureVerifier signatureVerifier = new JXAdESSignatureVerifier();
        VerificationResult verificationResult = signatureVerifier.verify(signedData);

        showErrors(verificationResult);

        System.out.println(new String(signedData));
    }
}
