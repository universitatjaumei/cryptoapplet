package es.uji.apps.cryptoapplet.crypto.facturae;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.junit.Before;
import org.junit.Test;

import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;

public class FacturaeTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new FileInputStream(inputDir + "in-facturae.xml"));
    }

    @Test
    public void facturae() throws Exception
    {
        // Sign

        Formatter formatter = new FacturaeFormatter(certificate, privateKey, provider);
        SignatureResult signatureResult = formatter.format(signatureOptions);

        showErrors(signatureResult, inputDir + "out-facturae.xml");

        // Verify

        Validator validator = new FacturaeValidator(certificate, provider);

        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setSignedData(new FileInputStream(inputDir + "out-facturae.xml"));

        ValidationResult verificationResult = validator.validate(validationOptions);

        showErrors(verificationResult);
    }
}
