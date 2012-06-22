package es.uji.apps.cryptoapplet.crypto.raw;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;

import org.junit.Before;
import org.junit.Test;

import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class RawSignatureTest extends BaseCryptoAppletTest
{
    private static final String OUTPUT_FILE = outputDir + "out-raw.bin";

    @Before
    public void init()
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void raw() throws Exception
    {
        // Sign

        Formatter formatter = new RawFormatter(certificate, privateKey, provider);
        SignatureResult signatureResult = formatter.format(signatureOptions);

        showErrors(signatureResult, OUTPUT_FILE);

        // Verify

        byte[] signedData = StreamUtils.inputStreamToByteArray(new FileInputStream(OUTPUT_FILE));

        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setOriginalData(data);
        validationOptions.setSignedData(signedData);

        Validator validator = new RawValidator(certificate, provider);
        assertTrue(validator.validate(validationOptions).isValid());
    }
}