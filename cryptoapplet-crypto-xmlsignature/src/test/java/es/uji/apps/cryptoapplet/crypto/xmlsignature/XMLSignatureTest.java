package es.uji.apps.cryptoapplet.crypto.xmlsignature;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

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

public class XMLSignatureTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws ConfigurationLoadException
    {
        Configuration configuration = new ConfigManager().getConfiguration();
        signatureOptions = new SignatureOptions(configuration);
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void xmlsignature() throws Exception
    {
        // Sign

        Formatter formatter = new XMLSignatureFormatter(certificate, privateKey, provider);
        SignatureResult signatureResult = formatter.format(signatureOptions);

        showErrors(signatureResult, outputDir + "out1.xml");

        signatureOptions.setDataToSign(new FileInputStream(outputDir + "out1.xml"));
        signatureResult = formatter.format(signatureOptions);

        showErrors(signatureResult, outputDir + "out2.xml");

        // Verify

        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setSignedData(new FileInputStream(outputDir + "out2.xml"));

        Validator validator = new XMLSignatureValidator(certificate, provider);
        assertTrue(validator.validate(validationOptions).isValid());
    }
}