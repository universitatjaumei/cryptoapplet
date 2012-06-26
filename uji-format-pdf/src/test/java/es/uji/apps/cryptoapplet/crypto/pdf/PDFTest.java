package es.uji.apps.cryptoapplet.crypto.pdf;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import es.uji.apps.cryptoapplet.config.ConfigManager;
import es.uji.apps.cryptoapplet.config.ConfigurationLoadException;
import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class PDFTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws IOException, ConfigurationLoadException
    {
        data = StreamUtils.inputStreamToByteArray(new FileInputStream(inputDir + "in-pdf.pdf"));

        Configuration configuration = new ConfigManager().getConfiguration();
        Map<String, String> options = configuration.getFormatRegistry().getFormat("PDF")
                .getConfiguration();

        // TODO Support bindValues
        // Map<String, String> bindValues = new HashMap<String, String>();
        // bindValues.put("%x", "3439-2134-1371-0998");
        // signatureOptions.setVisibleSignatureTextBindValues(bindValues);

        options.put("signature.textPattern", "%s con referencia %x a las %t");
        options.put("signature.repeatAxis", "Y");

        signatureOptions = new SignatureOptions(configuration);
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    @Ignore
    public void pdf() throws Exception
    {
        // Sign

        Formatter signFormatProvider = new PDFFormatter(certificate, new X509Certificate[] {},
                privateKey, provider);
        SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

        showErrors(signatureResult, inputDir + "out-pdf.pdf");

        data = StreamUtils.inputStreamToByteArray(new FileInputStream(inputDir + "out-pdf.pdf"));
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));

        signFormatProvider = new PDFFormatter(certificate, new X509Certificate[] {}, privateKey,
                provider);
        signatureResult = signFormatProvider.format(signatureOptions);

        showErrors(signatureResult, inputDir + "out-pdf2.pdf");

        // Verify

        Validator signatureVerifier = new PDFValidator(certificate, new X509Certificate[] {},
                provider);
        ValidationOptions validatioOptions = new ValidationOptions();
        validatioOptions.setSignedData(new FileInputStream(inputDir + "out-pdf2.pdf"));

        ValidationResult verificationResult = signatureVerifier.validate(validatioOptions);

        showErrors(verificationResult);
    }
}