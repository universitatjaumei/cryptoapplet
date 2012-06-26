package es.uji.apps.cryptoapplet.crypto.pdf;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;

import org.apache.log4j.Logger;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;

import es.uji.apps.cryptoapplet.crypto.BaseValidator;
import es.uji.apps.cryptoapplet.crypto.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.ValidationException;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;

public class PDFValidator extends BaseValidator implements Validator
{
    private Logger log = Logger.getLogger(PDFValidator.class);

    public PDFValidator(X509Certificate certificate, X509Certificate[] caCertificates,
            Provider provider) throws CertificateNotFoundException
    {
        super(certificate, caCertificates, provider);
    }

    @SuppressWarnings("unchecked")
    @Override
    public ValidationResult validate(ValidationOptions validationOptions)
            throws ValidationException
    {
        log.debug("Verifying PDF signature");

        ValidationResult verificationResult = new ValidationResult();

        log.debug("Loading default CA certificates");

        KeyStore kall = PdfPKCS7.loadCacertsKeyStore();

        for (X509Certificate caCertificate : caCertificates)
        {
            try
            {
                kall.setCertificateEntry(caCertificate.getSubjectDN().getName(), caCertificate);
            }
            catch (Exception e)
            {
                log.error("CA certificate " + caCertificate.getSubjectDN().getName()
                        + " can not be added to global keystore", e);
            }
        }

        PdfReader reader = null;

        try
        {
            log.debug("Parsing input PDF document");

            reader = new PdfReader(validationOptions.getOriginalData());
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

            Object fails[] = PdfPKCS7.verifyCertificates(pkc, kall, null, cal);

            if (fails != null)
            {
                verificationResult.setValid(false);

                for (Object error : fails)
                {
                    verificationResult.addError((String) error);
                }

                return verificationResult;
            }
        }

        verificationResult.setValid(true);

        return verificationResult;
    }
}