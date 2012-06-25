package es.uji.apps.cryptoapplet.crypto.jxades;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import es.uji.apps.cryptoapplet.crypto.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureException;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationException;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;
import es.uji.apps.cryptoapplet.crypto.xades.XAdESFormatter;
import es.uji.apps.cryptoapplet.crypto.xades.XAdESValidator;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class XAdESTest extends BaseCryptoAppletTest
{
    private static final String OUTPUT_FILE = outputDir + "out-xades-";

    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void jxadesEnvelopedWithoutCosign() throws Exception
    {
        signAndVerify(OUTPUT_FILE + "enveloped.xml");
    }

    @Test
    public void jxadesEnvelopedCosign() throws Exception
    {
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

        byte[] signedData = StreamUtils.inputStreamToByteArray(new FileInputStream(fileName));

        ValidationOptions validationOptions = new ValidationOptions();
        validationOptions.setOriginalData(data);
        validationOptions.setSignedData(signedData);

        Validator validator = new XAdESValidator(certificate, provider);
        assertTrue(validator.validate(validationOptions).isValid());
    }

    @Test
    public void jxadesDetachedCosign() throws Exception
    {
        // CoSign

        byte[] data = "<?xml version=\"1.0\"?><root><d id=\"D0\">a</d><d id=\"D1\">b</d></root>"
                .getBytes();

        signatureOptions.setEnveloped(false);
        signatureOptions.setCoSignEnabled(true);
        signatureOptions.setReferences(Arrays.asList(new String[] { "D0", "D1" }));

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

        data = StreamUtils.inputStreamToByteArray(new FileInputStream(inputDir
                + "out-jxades-detached-cosign.xml"));

        XAdESValidator validator = new XAdESValidator(certificate, provider);

        ValidationOptions options = new ValidationOptions();
        options.setSignedData(data);

        ValidationResult validationResult = validator.validate(options);
        showErrors(validationResult);
    }
}
