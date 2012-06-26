package es.uji.apps.cryptoapplet.crypto.cms;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.cert.X509Certificate;

import org.junit.Before;
import org.junit.Test;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.ConfigurationLoadException;
import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;

public class CMSTest extends BaseCryptoAppletTest
{
    private static final String OUTPUT_FILE = outputDir + "out-cms.bin";
    
    @Before
    public void init() throws ConfigurationLoadException
    {
        Configuration configuration = new ConfigManager().getConfiguration();
        signatureOptions = new SignatureOptions(configuration);
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

        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setOriginalData(signatureOptions.getDataToSign());
        validationOptions.setSignedData(new FileInputStream(OUTPUT_FILE));

        Validator validator = new CMSValidator(certificate, new X509Certificate[] {}, provider);
        assertTrue(validator.validate(validationOptions).isValid());
    }
}
