package es.uji.apps.cryptoapplet.crypto.xades;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Map;

import org.junit.Test;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureException;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationException;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class XAdESTest extends BaseCryptoAppletTest
{
    private static final String OUTPUT_FILE = outputDir + "out-xades-";

    @Test
    public void jxadesEnvelopedWithoutCosign() throws Exception
    {
        Configuration configuration = new ConfigManager().getConfiguration();
        signatureOptions = new SignatureOptions(configuration);
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
        
        signAndVerify(OUTPUT_FILE + "enveloped.xml");
    }

    @Test
    public void jxadesEnvelopedCosign() throws Exception
    {
        Configuration configuration = new ConfigManager().getConfiguration();
        signatureOptions = new SignatureOptions(configuration);
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
        
        signatureOptions.setCoSignEnabled(true);
        signAndVerify(OUTPUT_FILE + "enveloped-cosign.xml");
    }

    private void signAndVerify(String fileName) throws SignatureException, IOException,
            FileNotFoundException, CertificateNotFoundException, ValidationException
    {
        // Sign

        Formatter signFormatProvider = new XAdESFormatter(certificate, privateKey, provider);
        SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

        showErrors(signatureResult, fileName);

        // Verify

        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setOriginalData(signatureOptions.getDataToSign());
        validationOptions.setSignedData(new FileInputStream(fileName));

        Validator validator = new XAdESValidator(certificate, provider);
        assertTrue(validator.validate(validationOptions).isValid());
    }

    @Test
    public void jxadesDetachedCosign() throws Exception
    {
        Configuration configuration = new ConfigManager().getConfiguration();
        Map<String, String> options = configuration.getFormatRegistry().getFormat("XADES").getConfiguration();
        options.put("references", "D0,D1");
        
        signatureOptions = new SignatureOptions(configuration);
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
        
        // CoSign

        byte[] data = "<?xml version=\"1.0\"?><root><d id=\"D0\">a</d><d id=\"D1\">b</d></root>"
                .getBytes();

        signatureOptions.setEnveloped(false);
        signatureOptions.setCoSignEnabled(true);

        for (int i = 0; i < 3; i++)
        {
            signatureOptions.setDataToSign(new ByteArrayInputStream(data));

            Formatter signFormatProvider = new XAdESFormatter(certificate, privateKey, provider);
            SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

            showErrors(signatureResult, inputDir + "out-jxades-detached-cosign.xml");

            data = StreamUtils.inputStreamToByteArray(new FileInputStream(inputDir
                    + "out-jxades-detached-cosign.xml"));
        }

        // Verify

        XAdESValidator validator = new XAdESValidator(certificate, provider);

        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setSignedData(new FileInputStream(inputDir + "out-jxades-detached-cosign.xml"));

        ValidationResult validationResult = validator.validate(validationOptions);
        showErrors(validationResult);
    }
}
