package es.uji.apps.cryptoapplet.crypto.xmlsignature;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;

import org.junit.Before;
import org.junit.Test;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.ConfigurationLoadException;
import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;

public class XMLSignatureTest extends BaseCryptoAppletTest
{
    private static final String OUTPUT_FILE = outputDir + "out-xmlsignature.xml";

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

        showErrors(signatureResult, OUTPUT_FILE);

        // Verify

        Validator validator = new XMLSignatureValidator(certificate, provider);
        
        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setSignedData(new FileInputStream(OUTPUT_FILE));

        ValidationResult verificationResult = validator.validate(validationOptions);

        showErrors(verificationResult);
    }
}