package es.uji.security.keystore.pkcs12;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.keystore.IKeyStore;

public class PKCS12KeyStore implements IKeyStore
{
    private KeyStore ks = null;
    char[] _pin = null;

    public void load(char[] pin) throws KeyStoreException, NoSuchAlgorithmException, IOException,
            CertificateException, Exception
    {
        // Error, we need the path or the input stream of the pkcs12
    }

    public void load(InputStream in, char[] pin) throws KeyStoreException,
            NoSuchAlgorithmException, IOException, CertificateException, Exception
    {
        ks = KeyStore.getInstance("pkcs12");
        ks.load(in, pin);
        _pin = pin;
    }

    public Enumeration<String> aliases() throws KeyStoreException, Exception
    {
        return ks.aliases();
    }

    public Certificate getCertificate(String alias) throws KeyStoreException, Exception
    {
        return ks.getCertificate(alias);
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
        return ks.getKey(alias, _pin);
    }

    public Provider getProvider()
    {
        return new BouncyCastleProvider();
    }

    public SupportedKeystore getName()
    {
        return SupportedKeystore.PKCS12;
    }

    public String getTokenName()
    {
        return "File";
    }

    public String getAliasFromCertificate(Certificate cer) throws KeyStoreException
    {
        X509Certificate xcer = (X509Certificate) cer, auxCer = null;
        String auxAlias = null;

        Enumeration<String> e = ks.aliases();
        
        while (e.hasMoreElements())
        {
            auxAlias = (String) e.nextElement();
            auxCer = (X509Certificate) ks.getCertificate(auxAlias);
            if ((auxCer.getIssuerDN().equals(xcer.getIssuerDN()))
                    && (auxCer.getSerialNumber().equals(xcer.getSerialNumber())))
            {
                return auxAlias;
            }
        }

        return null;
    }

    public byte[] signMessage(byte[] toSign, String alias) throws NoSuchAlgorithmException,
            Exception
    {
        byte[] b = null;
        return b;
    }

    public void cleanUp()
    {
        _pin = null;
    }
}
