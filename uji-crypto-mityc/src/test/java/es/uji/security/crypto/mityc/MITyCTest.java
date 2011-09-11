package es.uji.security.crypto.mityc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import es.uji.security.crypto.BaseCryptoAppletTest;
import es.uji.security.crypto.config.OS;

public class MITyCTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new FileInputStream(baseDir + "in-mityc.xml"));
    }

    @Test
    public void mityc() throws Exception
    {
        // Verify
        
        byte[] signedData = OS
                .inputStreamToByteArray(new FileInputStream(baseDir + "out-mityc.xml"));

        MitycXAdESSignatureValidator signatureValidator = new MitycXAdESSignatureValidator();

        Assert.assertTrue(signatureValidator.verify(signedData));
    }
}