package es.uji.security.crypto.pdf;

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import org.apache.log4j.Logger;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.VerificationException;
import com.itextpdf.text.pdf.PdfReader;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.crypto.config.ConfigManager;

public class PDFSignatureVerifier
{
    private Logger log = Logger.getLogger(PDFSignatureVerifier.class);

    @SuppressWarnings("unchecked")
    public VerificationResult verify(byte[] pdfData)
    {
        log.debug("Verifying PDF signature");

        VerificationResult verificationResult = new VerificationResult();

        log.debug("Loading default CA certificates");

        KeyStore kall = PdfPKCS7TSA.loadCacertsKeyStore();

        // Add all configured certificates to the main keystore

        ConfigManager conf = ConfigManager.getInstance();

        int numCertificates = 0;

        try
        {
            numCertificates = Integer.parseInt(conf.getProperty("DIGIDOC_CA_CERTS"));
            log.debug(numCertificates + " certificates configured in PDFSIG_CA_CERTS property");
        }
        catch (Exception e)
        {
            log.debug("Can not read DIGIDOC_CA_CERTS property", e);

            verificationResult.setValid(false);
            verificationResult.addError("Can not read DIGIDOC_CA_CERTS property");

            return verificationResult;
        }

        for (int i = 1; i <= numCertificates; i++)
        {
            try
            {
                log.debug("Adding certificate DIGIDOC_CA_CERTS" + i + " to the global keystore");

                Certificate certificate = ConfigManager.readCertificate(conf
                        .getProperty("DIGIDOC_CA_CERT" + i));

                kall.setCertificateEntry("host ca " + i, certificate);
            }
            catch (Exception e)
            {
                log.error("CA certificate can not be added to global keystore", e);
            }
        }



        PdfReader reader = null;

        try
        {
            log.debug("Parsing input PDF document");

            reader = new PdfReader(pdfData);
        }
        catch (IOException ioe)
        {
            log.error("Can not parse input PDF document", ioe);

            verificationResult.setValid(false);
            verificationResult.addError("Can not parse input PDF document");

            return verificationResult;
        }

        AcroFields acroFields = reader.getAcroFields();
        ArrayList<String> signatureNameList = acroFields.getSignatureNames();

        for (String name : signatureNameList)
        {
            log.debug("Verifiying " + name + " signature");

            PdfPKCS7 pdfPKCS7 = acroFields.verifySignature(name);
            Calendar cal = pdfPKCS7.getSignDate();
            Certificate pkc[] = pdfPKCS7.getCertificates();

            if (!isSelfSigned((X509Certificate) pkc[0])) {
                List<VerificationException> errors = CertificateVerification.verifyCertificates(pkc, kall, cal);

                if (errors != null && !errors.isEmpty()) {
                    verificationResult.setValid(false);

                    for (VerificationException error : errors) {
                        verificationResult.addError(error.getMessage());
                    }

                    return verificationResult;
                }
            }
        }

        verificationResult.setValid(true);

        return verificationResult;
    }

    public boolean isSelfSigned(X509Certificate certificate) {
        return certificate.getIssuerDN().equals(certificate.getSubjectDN());
    }
}