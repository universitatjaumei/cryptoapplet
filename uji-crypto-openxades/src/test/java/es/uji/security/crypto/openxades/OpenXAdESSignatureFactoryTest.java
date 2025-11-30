package es.uji.security.crypto.openxades;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.OS;
import es.uji.security.crypto.test.BaseCryptoAppletTest;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.X509Certificate;

public class OpenXAdESSignatureFactoryTest extends BaseCryptoAppletTest
{
    @Before
    public void init() throws FileNotFoundException
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void signAndVerifyOpenXAdESDocuments() throws Exception
    {
        if (isSelfSignedCertificate(signatureOptions)) {
            System.out.println("No puedo calcular firmas XL con un certificado autofirmado (imposible validar por OCSP)");
            return;
        }

        ISignFormatProvider signFormatProvider = new OpenXAdESSignatureFactory();
        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);
        showErrors(signatureResult, "target/openxades-document.xml");

        byte[] signedData = OS.inputStreamToByteArray(new FileInputStream("target/openxades-document.xml"));
        OpenXAdESSignatureVerifier signatureVerifier = new OpenXAdESSignatureVerifier();
        VerificationResult verificationResult = signatureVerifier.verify(signedData);
        showErrors(verificationResult);
    }

    @Test
    public void verifyDigestOpenXAdESDocuments() throws Exception
    {
        for (String digestAlgorithm: new String[] {"sha1", "sha256"}) {
            byte[] signedData = OS.inputStreamToByteArray(
                    new FileInputStream("src/test/resources/openxades-" + digestAlgorithm + "-digest.xml"));

            OpenXAdESSignatureVerifier signatureVerifier = new OpenXAdESSignatureVerifier();
            VerificationResult verificationResult = signatureVerifier.verify(signedData);

            showErrors(verificationResult);
        }
    }

    public boolean isSelfSignedCertificate(SignatureOptions signatureOptions) {
        X509Certificate signingCertificate = signatureOptions.getCertificate();
        return signingCertificate.getIssuerDN().equals(signingCertificate.getSubjectDN());
    }
}