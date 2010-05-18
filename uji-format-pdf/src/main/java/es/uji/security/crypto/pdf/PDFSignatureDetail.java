package es.uji.security.crypto.pdf;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;

import es.uji.security.crypto.SignatureDetailInformation;
import es.uji.security.crypto.config.OS;

public class PDFSignatureDetail
{
    @SuppressWarnings("unchecked")
    public List<SignatureDetailInformation> getDetails(byte[] data) throws Exception
    {
        List<SignatureDetailInformation> result = new ArrayList<SignatureDetailInformation>();

        PdfReader reader = new PdfReader(data);

        AcroFields acroFields = reader.getAcroFields();
        ArrayList<String> signatureNameList = acroFields.getSignatureNames();

        for (String name : signatureNameList)
        {
            SignatureDetailInformation signatureDetailInformation = new SignatureDetailInformation();

            PdfPKCS7 pkcs7 = acroFields.verifySignature(name);

            Calendar signingTime = pkcs7.getSignDate();

            if (signingTime != null)
            {
                signatureDetailInformation.setSignatureTime(signingTime.getTime());
            }

            X509Certificate certificate = pkcs7.getSigningCertificate();

            if (certificate != null)
            {
                String cnField = certificate.getSubjectDN().getName();

                if (cnField != null)
                {
                    String[] fields = cnField.split(",");

                    for (String f : fields)
                    {
                        if (f.trim().startsWith("CN="))
                        {
                            signatureDetailInformation.setSignerCN(f.trim().substring(3));
                        }
                    }
                }
            }

            result.add(signatureDetailInformation);
        }

        return result;
    }
}