package es.uji.apps.cryptoapplet.crypto.cms;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.cert.X509Certificate;

import org.junit.Before;
import org.junit.Test;

import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class CMSTest extends BaseCryptoAppletTest
{
    private static final String OUTPUT_FILE = outputDir + "out-cms.bin";

    @Before
    public void init()
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void cms() throws Exception
    {
        // Sign

        Formatter formatter = new CMSFormatter(certificate, privateKey, provider);
        SignatureResult signatureResult = formatter.format(signatureOptions);

        showErrors(signatureResult, OUTPUT_FILE);

        // Verify

        byte[] signedData = StreamUtils.inputStreamToByteArray(new FileInputStream(OUTPUT_FILE));

        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setOriginalData(data);
        validationOptions.setSignedData(signedData);

        Validator validator = new CMSValidator(certificate, new X509Certificate[] {}, provider);
        assertTrue(validator.validate(validationOptions).isValid());
    }
}
