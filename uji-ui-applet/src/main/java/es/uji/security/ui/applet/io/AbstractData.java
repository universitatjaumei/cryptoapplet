package es.uji.security.ui.applet.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class AbstractData
{

    boolean mustHash = false;

    public static byte[] getMessageDigest(byte[] toHash)
    {
        byte[] digest = null;

        try
        {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(toHash);

            digest = md.digest();
            md.reset();

        }
        catch (NoSuchAlgorithmException e)
        {
            // TODO Auto-generated catch block
            // Null will be returned
            // e.printStackTrace();
        }

        return digest;
    }
    
    public static byte[] getMessageDigest(InputStream toHash_is) throws IOException
    {
        byte[] digest = null;

        try
        {
            MessageDigest md = MessageDigest.getInstance("SHA1");
         
            byte[] buffer = new byte[2048];
            int length = 0;

            while ((length = toHash_is.read(buffer)) >= 0)
            {
                md.update(buffer, 0, length);
            }
            
            digest = md.digest();
            md.reset();
        }
        catch (NoSuchAlgorithmException e)
        {
            // TODO Auto-generated catch block
            // Null will be returned
            // e.printStackTrace();
        }

        return digest;
    }
    

    public void setmustHash(boolean value)
    {
        this.mustHash = value;
    }

    /**
     * 
     * Allow to connect to a untrusted https sources in order to get the data to sign This "empty"
     * trustManager is not set when indicated through sslServerCertificate Verification.
     * 
     **/
    public void UrlSetup()
    {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
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
        } };

        // Install the all-trusting trust manager
        try
        {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        }
        catch (Exception e)
        {
        }
    }

    // Test
    public static void main(String[] args)
    {
        System.out.println(es.uji.security.util.HexDump.xdump(getMessageDigest("a".getBytes())));
    }
}
