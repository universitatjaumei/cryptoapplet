package es.uji.security.keystore.mscapi;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.openoces.opensign.wrappers.microsoftcryptoapi.MicrosoftCryptoApi;

import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.keystore.IKeyStore;


public class MsCapiKeyStore implements IKeyStore
{
    private MicrosoftCryptoApi _mscapi;
    private Logger log = Logger.getLogger(MsCapiKeyStore.class);

    public MsCapiKeyStore()
    {
        _mscapi = new MicrosoftCryptoApi();
    }

    public String getAliasFromCertificate(javax.security.cert.X509Certificate cer)
    {
        return cer.getIssuerDN() + " Serial=" + cer.getSerialNumber();
    }

    public String getAliasFromCertificate(Certificate cer)
    {

        X509Certificate xcer = (X509Certificate) cer;

        String strAux = "";
        strAux += xcer.getIssuerDN();
        strAux += " Serial=" + xcer.getSerialNumber();

        return strAux;
    }

    public void load(char[] pin) throws KeyStoreException, NoSuchAlgorithmException, IOException,
            CertificateException
    {
    }

    public Enumeration aliases() throws KeyStoreException, Exception
    {
        log.debug("Loading aliases from keystore");
        
        String strAux = "";
        byte[][] rs = null;

        try
        { 
            rs = _mscapi.getCertificatesInSystemStore("My");
        }
        catch (Exception e)
        {
            log.error("Error loading the certificate list from the keystore", e);
        }

        Vector<String> vcerts = new Vector<String>();

        if (rs == null)
        {
            return null;
        }

        // log.debug("Got certificate length: " + rs.length);

        for (int i = 0; i < rs.length; i++)
        {
            try
            {
                ByteArrayInputStream bIn = new ByteArrayInputStream(rs[i]);

                javax.security.cert.X509Certificate c = javax.security.cert.X509Certificate.getInstance(bIn);
                strAux = getAliasFromCertificate(c);

                vcerts.add(strAux);
            }
            catch (Exception e)
            {
                log.error("Error extracting alias from a certificate", e);
            }
        }

        log.debug(vcerts.size() + " aliases loaded");
        
        return Collections.enumeration(vcerts);
    }

    public Certificate getCertificate(String alias) throws KeyStoreException, Exception
    {
        log.debug("Loading certificate with alias " + alias);
        
        String strAux = "";

        byte[][] rs = _mscapi.getCertificatesInSystemStore("My");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = null;

        if (rs == null)
        {
            return null;
        }

        for (int i = 0; i < rs.length; i++)
        {
            try
            {
                ByteArrayInputStream bIn = new ByteArrayInputStream(rs[i]);

                javax.security.cert.X509Certificate c = javax.security.cert.X509Certificate
                        .getInstance(bIn);

                strAux = getAliasFromCertificate(c);

                if (strAux.equals(alias))
                {
                    ByteArrayInputStream certIs = new ByteArrayInputStream(rs[i]);
                    cert = (X509Certificate) cf.generateCertificate(certIs);
                    // System.out.println("Obtenido certificate cert= " + cert);
                }
            }
            catch (Exception e)
            {
                return null;
            }
        }
        return cert;
    }

    public Certificate[] getUserCertificates() throws KeyStoreException, Exception
    {
        log.debug("Loading user certificates from keystore " + getName());
        
        Vector<Certificate> certs = new Vector<Certificate>();

        for (Enumeration<?> e = aliases(); e.hasMoreElements();)
        {
            String alias = (String) e.nextElement();
            
            log.debug("Found certificate whith alias " + alias);
            certs.add(getCertificate(alias));
        }

        Certificate[] res = new Certificate[certs.size()];
        certs.toArray(res);

        return res;
    }

    public Key getKey(String alias) throws KeyStoreException, Exception
    {
        return new MSCAPIPrivateKey(alias);
    }

    public Provider getProvider()
    {
        return new MSCAPIProvider(); // Security.getProvider("UJI-MSCAPI");
    }

    public byte[] signMessage(byte[] toSign, String alias) throws NoSuchAlgorithmException,
            Exception
    {
        String strAux = "";

        byte[][] rs = _mscapi.getCertificatesInSystemStore("My");

        if (rs == null)
        {
            return null;
        }

        for (int i = 0; i < rs.length; i++)
        {
            try
            {
                ByteArrayInputStream bIn = new ByteArrayInputStream(rs[i]);

                javax.security.cert.X509Certificate c = javax.security.cert.X509Certificate
                        .getInstance(bIn);

                strAux = getAliasFromCertificate(c);

                if (strAux.equals(alias))
                {
                    return _mscapi.signMessage(toSign, rs[i]);
                }
            }
            catch (Exception e)
            {
                log.debug("Devolviendo NULL: Excepci�n " + e.getCause());
                return null;
            }
        }
        return null;
    }

    public byte[] signHash(byte[] toSign, String alias) throws NoSuchAlgorithmException, Exception
    {
        String strAux = "";

        byte[][] rs = _mscapi.getCertificatesInSystemStore("My");

        if (rs == null)
        {
            return null;
        }

        for (int i = 0; i < rs.length; i++)
        {
            try
            {
                ByteArrayInputStream bIn = new ByteArrayInputStream(rs[i]);
                javax.security.cert.X509Certificate c = javax.security.cert.X509Certificate
                        .getInstance(bIn);

                strAux = getAliasFromCertificate(c);

                if (strAux.equals(alias))
                {
                    return _mscapi.signHash(toSign, rs[i]);
                }
            }
            catch (Exception e)
            {
                return null;
            }
        }

        return null;
    }

    public SupportedKeystore getName()
    {
        return SupportedKeystore.MSCAPI;
    }

    public String getTokenName()
    {
        return "Windows Capi";
    }

    public void cleanUp()
    {
        _mscapi = null;
        Runtime.getRuntime().gc();
    }
}
