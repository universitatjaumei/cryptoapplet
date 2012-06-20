package es.uji.apps.cryptoapplet.crypto.pdf;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

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

        Formatter signFormatProvider = new PDFFormatter();
        SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

        showErrors(signatureResult, baseDir + "out-pdf.pdf");

        data = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir + "out-pdf.pdf"));
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));

        signFormatProvider = new PDFFormatter();
        signatureResult = signFormatProvider.format(signatureOptions);

        showErrors(signatureResult, baseDir + "out-pdf2.pdf");

        // Verify

        byte[] signedData = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir
                + "out-pdf2.pdf"));

        PDFValidator signatureVerifier = new PDFValidator();
        ValidationResult verificationResult = signatureVerifier.verify(signedData);

        showErrors(verificationResult);
    }
}