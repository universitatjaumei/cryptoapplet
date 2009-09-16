package es.uji.security.crypto.pdf;

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Calendar;

import org.apache.log4j.Logger;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;

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
        
        KeyStore kall = PdfPKCS7.loadCacertsKeyStore();
        
        // Add all configured certificates to the main keystore
        
        ConfigManager conf = ConfigManager.getInstance();
        
        int numCertificates = 0;
        
        try
        {
            numCertificates = Integer.parseInt(conf.getProperty("PDFSIG_CA_CERTS"));
            log.debug(numCertificates + " certificates configured in PDFSIG_CA_CERTS property");
        }
        catch (Exception e)
        {
            log.debug("Can not read PDFSIG_CA_CERTS property", e);
            
            verificationResult.setValid(false);
            verificationResult.addError("Can not read PDFSIG_CA_CERTS property");
            
            return verificationResult;
        }
        
        ClassLoader classLoader = PDFSignatureVerifier.class.getClassLoader();
        CertificateFactory certificateFactory = null;
        
        try
        {
            log.debug("Initializing certificate factory");
            
            certificateFactory = CertificateFactory.getInstance("X.509");
        }
        catch (CertificateException ce)
        {
            log.error("Can not initialize certificate factory", ce);
            
            verificationResult.setValid(false);
            verificationResult.addError("Can not initialize certificate factory");
            
            return verificationResult;
        }
        
        for (int i=1; i<=numCertificates; i++)
        {
            try
            {
                log.debug("Adding certificate PDFSIG_CA_CERT" + i + " to the global keystore");
                
                Certificate certificate = certificateFactory.generateCertificate(classLoader.getResourceAsStream(conf
                        .getProperty("PDFSIG_CA_CERT" + i)));
              
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
            
            reader = new PdfReader("src/main/resources/out.pdf");
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