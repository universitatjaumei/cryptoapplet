package es.uji.apps.cryptoapplet.crypto.facturae;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.junit.Before;
import org.junit.Test;

import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class FacturaeTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new FileInputStream(baseDir + "in-facturae.xml"));
    }

    @Test
    public void facturae() throws Exception
    {
        // Sign

        Formatter signFormatProvider = new FacturaeFormatter();
        SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

        showErrors(signatureResult, baseDir + "out-facturae.xml");

        // Verify

        byte[] signedData = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir
                + "out-facturae.xml"));

        FacturaeValidator signatureVerifier = new FacturaeValidator();
        ValidationResult verificationResult = signatureVerifier.verify(signedData);

        showErrors(verificationResult);
    }
}
