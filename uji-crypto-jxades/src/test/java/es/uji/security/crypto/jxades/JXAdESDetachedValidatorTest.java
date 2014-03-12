package es.uji.security.crypto.jxades;

import java.io.FileInputStream;

import org.junit.Test;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.OS;
import es.uji.security.crypto.test.BaseCryptoAppletTest;

public class JXAdESDetachedValidatorTest extends BaseCryptoAppletTest
{
    @Test
    public void jxadesDetached() throws Exception
    {
        byte[] signedData = OS.inputStreamToByteArray(new FileInputStream("/tmp/test.xml"));

        JXAdESSignatureVerifier signatureVerifier = new JXAdESSignatureVerifier();
        VerificationResult verificationResult = signatureVerifier.verify(signedData);

        showErrors(verificationResult);

        System.out.println(new String(signedData));
    }
}
