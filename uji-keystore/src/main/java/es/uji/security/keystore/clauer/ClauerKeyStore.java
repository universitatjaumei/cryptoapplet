package es.uji.security.keystore.clauer;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Vector;

import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.keystore.IKeyStore;

public class ClauerKeyStore implements IKeyStore
{
    private Clauer cl = new Clauer();
    private ClauerRunTime clr = new ClauerRunTime();
    private String passwd = null;
    private String device = null;
    Provider _provider;

    public ClauerKeyStore() throws Exception
    {
    	_provider= Security.getProvider("BC");
    	if (_provider==null){
    		throw new Exception("Provider BC is mandatory.");
    	}
    }

    public void load(char[] pin) throws KeyStoreException, NoSuchAlgorithmException, IOException,
            CertificateException, Exception
    {
        if (clr.isRunTimeRunning())
        {
            String[] devs = clr.enumerateDevices();
            if (devs.length == 0)
            {
                throw new KeyStoreException("NoCluauersPlugged");
            }
            else
            {
                if (pin != null)
                {
                    if (!cl.openAuth(devs[0], new String(pin)))
                    {
                        throw new KeyStoreException("IncorrectPassword");
                    }
                    else
                    {
                        device = devs[0];
                        passwd = new String(pin);
                        cl.close();
                    }
                }
                else
                {
                    cl.open(devs[0]);
                    device = devs[0];
                    cl.close();
                }
            }
        }
        else
        {
            throw new KeyStoreException("RuntimeNotRunning");
        }
    }

    public Enumeration<String> aliases() throws KeyStoreException, Exception
    {
        Vector<String> vs = new Vector<String>();

        if (device != null)
        {
            cl.open(device);
            String[] aliases = cl.getCertificateAliases();
            for (int i = 0; i < aliases.length; i++)
            {
                vs.add(aliases[i]);
            }
        }
        return Collections.enumeration(vs);
    }

    public Certificate getCertificate(String alias) throws KeyStoreException, Exception
    {
        if (device != null)
        {
            cl.open(device);
            Certificate cer = cl.getCertificate(alias);
            return cer;
        }

        return null;
    }

    public String getAliasFromCertificate(Certificate cer) throws Exception
    {

        if (device != null)
            cl.open(device);

        X509Certificate auxCer = null, xcer = (X509Certificate) cer;

        if (device != null)
        {
            String[] aliases = cl.getCertificateAliases();

            for (String alias : aliases)
            {
                cl.open(device);
                auxCer = (X509Certificate) cl.getCertificate(alias);
                if ((auxCer.getIssuerDN().equals(xcer.getIssuerDN()))
                        && (auxCer.getSerialNumber().equals(xcer.getSerialNumber())))
                {
                    return alias;
                }
            }
        }
        return null;
    }

    public Certificate[] getUserCertificates() throws KeyStoreException, Exception
    {

        Vector<Certificate> certs = new Vector<Certificate>();
        Certificate tmp_cert;

        for (Enumeration<String> e = this.aliases(); e.hasMoreElements();)
        {
            tmp_cert = this.getCertificate((String) e.nextElement());
            certs.add(tmp_cert);
        }

        Certificate[] res = new Certificate[certs.size()];
        certs.toArray(res);

        return res;
    }

    public Key getKey(String alias) throws KeyStoreException, Exception
    {
        if (device != null && passwd != null)
        {
            cl.openAuth(device, passwd);
            PrivateKey k = cl.getPrivateKey(alias);
            return k;
        }

        return null;
    }

    public Provider getProvider()
    {
    	return _provider;
    }
    
    public void setProvider(Provider provider)
    {
    	provider= _provider;
    }

    public byte[] signMessage(byte[] toSign, String alias) throws NoSuchAlgorithmException,
            Exception
    {
        byte[] b = null;
        return b;
    }

    public SupportedKeystore getName()
    {
        return SupportedKeystore.CLAUER;
    }

    public String getTokenName()
    {
        return "Clauer";
    }

    public void cleanUp()
    {
    }
}
