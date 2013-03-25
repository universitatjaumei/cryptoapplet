package es.uji.apps.cryptoapplet.crypto.xades;

import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.junit.AbstractCryptoTest;
import es.uji.apps.cryptoapplet.crypto.junit.KeyStoreAnfActivo;
import es.uji.apps.cryptoapplet.crypto.junit.SignEnvironment;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureFormatter;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidationOptions;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidationResult;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class XAdESTest extends AbstractCryptoTest
{
    private SignEnvironment environment;

    @Before
    public void init() throws Exception
    {
        environment = new SignEnvironment(new KeyStoreAnfActivo());
    }

    @Test
    public void xadesEnvelopedWithoutCosign() throws Exception
    {
        byte[] signedData = sign(XAdESSignatureFormatter.class, environment);
        System.out.println(new String(signedData));
        assertNotNull(signedData);
        assertTrue(signedData.length > 0);

        SignatureValidationResult validationResult = validate(XAdESSignatureValidator.class, environment, signedData);
        assertTrue(validationResult.isValid());
    }

    @Test
    public void xadesEnvelopedCosign() throws Exception
    {
        environment.enableCosign();

        byte[] signedData = sign(XAdESSignatureFormatter.class, environment);
        System.out.println(new String(signedData));
        assertNotNull(signedData);
        assertTrue(signedData.length > 0);

        SignatureValidationResult validationResult = validate(XAdESSignatureValidator.class, environment, signedData);
        assertTrue(validationResult.isValid());
    }

    @Test
    public void xadesDetachedCosign() throws Exception
    {
        Configuration configuration = environment.getConfiguration();
        Map<String, String> options = configuration.getFormatRegistry().getFormat("XADES")
                .getConfigurationOptions();
        options.put("references", "D0,D1");

        environment.enableCosign();
        environment.disableEnveloped();

        // CoSign

        byte[] data = "<?xml version=\"1.0\"?><root><d id=\"D0\">a</d><d id=\"D1\">b</d></root>"
                .getBytes();

        for (int i = 0; i < 3; i++)
        {
            environment.setData(data);

            SignatureFormatter signFormatProvider = new XAdESSignatureFormatter(environment.getCertificate(),
                    environment.getPrivateKey(), environment.getProvider());
            data = signFormatProvider.format(environment.getSignatureOptions());
        }

        System.out.println(new String(data));
        assertNotNull(data);
        assertTrue(data.length > 0);

        // Verify

        XAdESSignatureValidator validator = new XAdESSignatureValidator(environment.getCertificate(),
                environment.getProvider());

        SignatureValidationOptions signatureValidationOptions = new SignatureValidationOptions();
        signatureValidationOptions.setSignedData(new ByteArrayInputStream(data));

        validator.validate(signatureValidationOptions);
    }
}