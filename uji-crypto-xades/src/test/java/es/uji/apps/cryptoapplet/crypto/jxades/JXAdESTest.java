package es.uji.apps.cryptoapplet.crypto.jxades;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;
import es.uji.apps.cryptoapplet.crypto.xades.XAdESFormatter;
import es.uji.apps.cryptoapplet.crypto.xades.XAdESValidator;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class JXAdESTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void jxadesEnvelopedWithoutCosign() throws Exception
    {
        // Sign

        Formatter signFormatProvider = new XAdESFormatter();
        SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

        showErrors(signatureResult, baseDir + "out-jxades-enveloped.xml");

        // Verify

        byte[] signedData = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir
                + "out-jxades.xml"));

        XAdESValidator signatureVerifier = new XAdESValidator();
        ValidationResult ValidationResult = signatureVerifier.verify(signedData);

        showErrors(ValidationResult);
    }

    @Test
    public void jxadesEnvelopedCosign() throws Exception
    {
        // Sign

        signatureOptions.setCoSignEnabled(true);

        Formatter signFormatProvider = new XAdESFormatter();
        SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

        showErrors(signatureResult, baseDir + "out-jxades-enveloped-cosign.xml");

        // Verify

        byte[] signedData = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir
                + "out-jxades.xml"));

        XAdESValidator signatureVerifier = new XAdESValidator();
        ValidationResult ValidationResult = signatureVerifier.verify(signedData);

        showErrors(ValidationResult);
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

            Formatter signFormatProvider = new XAdESFormatter();
            SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

            showErrors(signatureResult, baseDir + "out-jxades-detached-cosign.xml");

            data = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir
                    + "out-jxades-detached-cosign.xml"));
        }

        // Verify

        data = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir
                + "out-jxades-detached-cosign.xml"));

        XAdESValidator signatureVerifier = new XAdESValidator();
        ValidationResult ValidationResult = signatureVerifier.verify(data);

        showErrors(ValidationResult);
    }
}
