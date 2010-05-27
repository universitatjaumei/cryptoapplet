package es.uji.security.crypto.config;

import java.security.cert.X509Certificate;

public class CertificateUtils
{
    public static String getCn(X509Certificate certificate)
    {
        String cn = "";
        
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
                        cn = f.trim().substring(3);
                    }
                }
            }
        }
        
        return cn;
    }
}
