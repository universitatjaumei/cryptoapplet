package es.uji.security.crypto.pades;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.config.OS;
import es.uji.security.crypto.test.BaseCryptoAppletTest;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class PadesTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws IOException
    {
        data = OS.inputStreamToByteArray(new FileInputStream("src/test/resources/in-pdf.pdf"));
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
        signatureOptions.setTsaURL("http://psis.catcert.net/psis/catcert/tsp");
    }

    @Test
    public void pdf() throws Exception
    {
        // Sign

        ISignFormatProvider signFormatProvider = new PAdESSignatureFactory();
        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);

        showErrors(signatureResult, "target/out-pdf.pdf");
    }
}