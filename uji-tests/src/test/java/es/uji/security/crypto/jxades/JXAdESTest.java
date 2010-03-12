package es.uji.security.crypto.jxades;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.junit.Before;
import org.junit.Test;

import es.uji.security.BaseCryptoAppletTest;
import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.OS;

public class JXAdESTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void jxades() throws Exception
    {
        // Sign

        ISignFormatProvider signFormatProvider = new JXAdESSignatureFactory();
        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);

        showErrors(signatureResult, baseDir + "out-jxades.xml");

        // Verify

        byte[] signedData = OS.inputStreamToByteArray(new FileInputStream(baseDir
                + "out-jxades.xml"));

        JXAdESSignatureVerifier signatureVerifier = new JXAdESSignatureVerifier();
        VerificationResult verificationResult = signatureVerifier.verify(signedData);

        showErrors(verificationResult);
    }
}
