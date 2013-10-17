package es.uji.apps.cryptoapplet.ui.auth;

import org.junit.Test;

import java.util.Date;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class TokenGeneratorTest
{
    @Test
    public void tokenGeneration() throws Exception
    {
        TokenGenerator tokenGenerator = new TokenGenerator();

        String appName = "APA";
        String timestamp = String.valueOf(new Date().getTime());

        String tokenData = String.format("%s:%s", appName, timestamp);
        String signature = tokenGenerator.generateToken(tokenData);

        assertNotNull(signature);
        assertTrue(signature.length() > 0);

        boolean signatureIsValid = tokenGenerator.verifyToken(tokenData, signature);

        assertTrue(signatureIsValid);
    }
}
