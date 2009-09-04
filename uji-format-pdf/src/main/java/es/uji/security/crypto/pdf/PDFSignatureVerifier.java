package es.uji.security.crypto.pdf;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Properties;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;

import es.uji.security.crypto.VerificationResult;
import es.uji.security.util.ConfigHandler;

public class PDFSignatureVerifier
{
    @SuppressWarnings("unchecked")
    public VerificationResult verify(byte[] pdfData) throws CertificateException, KeyStoreException, IOException
    {
        KeyStore kall = PdfPKCS7.loadCacertsKeyStore();
        
        // Add all configured certificates to the main keystore
        
        Properties prop = ConfigHandler.getProperties();
        
        int numCertificates = Integer.parseInt(prop.getProperty("PDFSIG_CA_CERTS"));
        
        ClassLoader classLoader = PDFSignatureVerifier.class.getClassLoader();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        
        for (int i=1; i<=numCertificates; i++)
        {
            Certificate certificate = certificateFactory.generateCertificate(classLoader.getResourceAsStream(prop
                    .getProperty("PDFSIG_CA_CERT" + i)));
          
            kall.setCertificateEntry("host ca " + i, certificate);
        }
        
        PdfReader reader = new PdfReader("src/main/resources/out.pdf");
        
        AcroFields acroFields = reader.getAcroFields();
        ArrayList<String> signatureNameList = acroFields.getSignatureNames();
        
        for (String name : signatureNameList)
        {
            PdfPKCS7 pdfPKCS7 = acroFields.verifySignature(name);
            Calendar cal = pdfPKCS7.getSignDate();
            Certificate pkc[] = pdfPKCS7.getCertificates();

            Object fails[] = PdfPKCS7.verifyCertificates(pkc, kall, null, cal);
            
            if (fails == null)
            {
                System.out.println("Certificates verified against the KeyStore");
            }
            else
            {
                System.out.println("Certificate failed: " + fails[1]);
            }
        }
        
        VerificationResult verificationResult = new VerificationResult();
        verificationResult.setValid(true);
        
        return verificationResult;
    }
}