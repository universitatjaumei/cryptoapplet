package es.uji.apps.cryptoapplet.crypto.facturae;

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
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;

public class FacturaeTest extends BaseCryptoAppletTest
{
    private static final String OUTPUT_FILE = outputDir + "out-facturae.xml";

    @Before
    public void init() throws FileNotFoundException, ConfigurationLoadException
    {
        Configuration configuration = new ConfigManager().getConfiguration();
        signatureOptions = new SignatureOptions(configuration);
        signatureOptions.setDataToSign(new FileInputStream(inputDir + "in-facturae.xml"));
    }

    @Test
    public void facturae() throws Exception
    {
        // Sign

        Formatter formatter = new FacturaeFormatter(certificate, privateKey, provider);
        SignatureResult signatureResult = formatter.format(signatureOptions);

        showErrors(signatureResult, OUTPUT_FILE);

        // Verify

        Validator validator = new FacturaeValidator(certificate, provider);

        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setSignedData(new FileInputStream(OUTPUT_FILE));

        ValidationResult verificationResult = validator.validate(validationOptions);

        showErrors(verificationResult);
    }
}
