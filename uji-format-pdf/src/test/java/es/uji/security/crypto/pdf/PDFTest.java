package es.uji.security.crypto.pdf;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import es.uji.security.crypto.BaseCryptoAppletTest;
import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.StreamUtils;

public class PDFTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws IOException
    {
        data = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir + "in-pdf.pdf"));
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));

        Map<String, String> bindValues = new HashMap<String, String>();
        bindValues.put("%x", "3439-2134-1371-0998");

        signatureOptions.setVisibleSignatureTextBindValues(bindValues);

        signatureOptions.setVisibleAreaTextPattern("%s con referencia %x a las %t");
        signatureOptions.setVisibleAreaRepeatAxis("Y");
    }

    @Test
    @Ignore
    public void pdf() throws Exception
    {
        // Sign

        ISignFormatProvider signFormatProvider = new PDFSignatureFactory();
        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);

        showErrors(signatureResult, baseDir + "out-pdf.pdf");

        data = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir + "out-pdf.pdf"));
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));

        signFormatProvider = new PDFSignatureFactory();
        signatureResult = signFormatProvider.formatSignature(signatureOptions);

        showErrors(signatureResult, baseDir + "out-pdf2.pdf");

        // Verify

        byte[] signedData = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir
                + "out-pdf2.pdf"));

        PDFSignatureVerifier signatureVerifier = new PDFSignatureVerifier();
        VerificationResult verificationResult = signatureVerifier.verify(signedData);

        showErrors(verificationResult);
    }
}