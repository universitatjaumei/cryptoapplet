package es.uji.security.crypto.openxades;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import es.uji.security.crypto.BaseCryptoAppletTest;
import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.StreamUtils;
import es.uji.security.crypto.VerificationResult;

public class OpenXAdESTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    @Ignore
    public void openxades() throws Exception
    {
        // Sign

        ISignFormatProvider signFormatProvider = new OpenXAdESSignatureFactory();
        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);

        showErrors(signatureResult, baseDir + "out-openxades.xml");

        // Verify

        byte[] signedData = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir
                + "out-openxades.xml"));

        OpenXAdESSignatureVerifier signatureVerifier = new OpenXAdESSignatureVerifier();
        VerificationResult verificationResult = signatureVerifier.verify(signedData);

        showErrors(verificationResult);
    }
}
