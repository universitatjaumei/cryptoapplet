package es.uji.apps.cryptoapplet.crypto.raw;

import es.uji.apps.cryptoapplet.crypto.junit.AbstractCryptoTest;
import es.uji.apps.cryptoapplet.crypto.junit.KeyStoreAnfActivo;
import es.uji.apps.cryptoapplet.crypto.junit.SignEnvironment;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidationResult;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class RawTest extends AbstractCryptoTest
{
    private SignEnvironment environment;

    @Before
    public void init() throws Exception
    {
        environment = new SignEnvironment(new KeyStoreAnfActivo());
    }

    @Test
    public void raw() throws Exception
    {
        byte[] signedData = sign(RawSignatureFormatter.class, environment);
        assertNotNull(signedData);
        assertTrue(signedData.length > 0);

        SignatureValidationResult validationResult = validate(RawSignatureValidator.class, environment, signedData);
        assertTrue(validationResult.isValid());
    }
}