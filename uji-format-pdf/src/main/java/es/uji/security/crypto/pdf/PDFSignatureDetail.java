package es.uji.security.crypto.pdf;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;

import es.uji.security.crypto.CryptoCoreException;
import es.uji.security.crypto.IDetailInformationGenerator;
import es.uji.security.crypto.SignatureDetailInformation;

public class PDFSignatureDetail implements IDetailInformationGenerator
{
    @SuppressWarnings("unchecked")
    public List<SignatureDetailInformation> getDetails(byte[] data) throws CryptoCoreException
    {
        List<SignatureDetailInformation> result = new ArrayList<SignatureDetailInformation>();

        PdfReader reader = null;
        
        try
        {
            reader = new PdfReader(data);
        }
        catch (IOException e)
        {
            return result;
        }

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