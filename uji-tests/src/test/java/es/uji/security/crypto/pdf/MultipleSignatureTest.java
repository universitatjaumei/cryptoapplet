package es.uji.security.crypto.pdf;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import es.uji.security.BaseCryptoAppletTest;
import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.OS;

public class MultipleSignatureTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws IOException
    {
        data = OS.inputStreamToByteArray(new FileInputStream(baseDir + "in-pdf.pdf"));
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void pdf() throws Exception
    {
        // Sign

        signatureOptions.setDocumentReference(UUID.randomUUID().toString());
//        signatureOptions.setDocumentReferenceVerificationUrl("http://www.uji.es");
        
        ISignFormatProvider signFormatProvider = new PDFSignatureFactory();
        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);

        showErrors(signatureResult, "target/out-pdf.pdf");

        data = OS.inputStreamToByteArray(new FileInputStream("target/out-pdf.pdf"));
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
        
        signFormatProvider = new PDFSignatureFactory();
        signatureResult = signFormatProvider.formatSignature(signatureOptions);

        showErrors(signatureResult, "target/out-pdf-with-two-signatures.pdf");        

        // Verify

        byte[] signedData = OS.inputStreamToByteArray(new FileInputStream("target/out-pdf-with-two-signatures.pdf"));

        PDFSignatureVerifier signatureVerifier = new PDFSignatureVerifier();
        VerificationResult verificationResult = signatureVerifier.verify(signedData);

        showErrors(verificationResult);
    }
}