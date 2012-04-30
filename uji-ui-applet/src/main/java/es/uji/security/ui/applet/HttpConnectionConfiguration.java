package es.uji.security.ui.applet;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;

public class HttpConnectionConfiguration
{
    private static Logger log = Logger.getLogger(HttpConnectionConfiguration.class);

    private SSLSocketFactory defaultSocketFactory;

    public HttpConnectionConfiguration()
    {
        defaultSocketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
    }

    public void setSSLServerCertificateVerificationTo(boolean validate)
    {
        if (validate)
        {
            enableValidatingSSLConnection();
        }
        else
        {
            enableNonValidatingSSLConnection();
        }
    }

    private void enableValidatingSSLConnection()
    {
        HttpsURLConnection.setDefaultSSLSocketFactory(defaultSocketFactory);
    }

    private void enableNonValidatingSSLConnection()
    {
        try
        {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, new TrustManager[] { new X509TrustManager()
            {
                public java.security.cert.X509Certificate[] getAcceptedIssuers()
                {
                    return null;
                }

                public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
                        String authType)
                {
                }

                public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
                        String authType)
                {
                }
            } }, new java.security.SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        }
        catch (Exception e)
        {
            log.error(e);
        }
    }
}