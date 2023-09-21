package es.uji.security.crypto.openxades;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.OS;
import es.uji.security.crypto.test.BaseCryptoAppletTest;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

public class OpenXAdESSignatureFactoryTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void jxadesEnvelopedWithoutCosign() throws Exception
    {
        // Sign

        ISignFormatProvider signFormatProvider = new OpenXAdESSignatureFactory();
        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);

        showErrors(signatureResult, "target/out-openxades.xml");

        // Verify

        byte[] signedData = OS.inputStreamToByteArray(new FileInputStream("target/out-openxades.xml"));

        OpenXAdESSignatureVerifier signatureVerifier = new OpenXAdESSignatureVerifier();
        VerificationResult verificationResult = signatureVerifier.verify(signedData);

        showErrors(verificationResult);
    }
}