package es.uji.apps.cryptoapplet.crypto.xmlsignature.odf;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.junit.Before;
import org.junit.Test;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;

public class ODFTest extends BaseCryptoAppletTest
{
    private static final String OUTPUT_FILE = outputDir + "out-odf.odt";

    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void odf() throws Exception
    {
        // Sign

        Formatter signFormatProvider = new ODFFormatter(certificate, privateKey, provider);
        SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

        showErrors(signatureResult, OUTPUT_FILE);

        // Verify

        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setOriginalData(signatureOptions.getDataToSign());
        validationOptions.setSignedData(new FileInputStream(OUTPUT_FILE));

        Validator validator = new ODFValidator(certificate, provider);
        assertTrue(validator.validate(validationOptions).isValid());
    }
}