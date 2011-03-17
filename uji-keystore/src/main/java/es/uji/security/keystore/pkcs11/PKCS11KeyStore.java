package es.uji.security.keystore.pkcs11;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.crypto.config.OS;
import es.uji.security.keystore.IKeyStore;

public class PKCS11KeyStore implements IKeyStore
{
    InputStream _isP11Config = null;
    char[] _pin = null;
    PKCS11Helper pk11h;
    String _name, _tokenName;

    private Provider _pk11provider = null;
    private KeyStore _p11KeyStore = null;
    private boolean helper = true;

    boolean privateInitialize = false;

    public PKCS11KeyStore(String p11LibPath) throws PKCS11HelperException
    {
        pk11h = new PKCS11Helper(p11LibPath);
        _name = pk11h.getName();

        _isP11Config = new ByteArrayInputStream(
                ("name = USER-PKCS11\r" + "library = " + p11LibPath + "\r").getBytes());
    }

    public PKCS11KeyStore(InputStream isP11Config, String p11LibPath, boolean helper)
            throws PKCS11HelperException
    {
     	
    	this.helper = helper;
        if (helper == true)
        {
            pk11h = new PKCS11Helper(p11LibPath);
            _name = pk11h.getName();
        }
        _isP11Config = isP11Config;
    }

    public PKCS11KeyStore(InputStream isP11Config, String p11LibPath) throws PKCS11HelperException
    {
        pk11h = new PKCS11Helper(p11LibPath);
        _name = pk11h.getName();
        _isP11Config = isP11Config;
    }

    public PKCS11KeyStore(InputStream isP11Config, String p11LibPath, String initArgs)
            throws PKCS11HelperException
    {
    	pk11h = new PKCS11Helper(p11LibPath, initArgs);
        _tokenName = pk11h.getName();
        _isP11Config = isP11Config;
    }

    public void load(char[] pin) throws KeyStoreException, NoSuchAlgorithmException, IOException,
            CertificateException, Exception
    {
        if (!privateInitialize)
        {
            if (pin != null)
            {
                if (_isP11Config != null)
                    load(_isP11Config, pin);
                else
                    throw new Exception(
                            "Must use load(InputStream in, char[] pin) to initialize this kind of store");
            }
        }
    }

    public void load(InputStream in, char[] pin) throws KeyStoreException,
            NoSuchAlgorithmException, IOException, CertificateException, Exception
    {
    	 try{
      		System.out.println("Input String initialized to: " + new String(OS.inputStreamToByteArray(in)));
      		in.reset();
      	}
      	catch(Exception e){}
    	
        if (!privateInitialize)
        {
            if (pin != null && in != null)
            {
                if (_pk11provider == null)
                {
                    _pk11provider = new sun.security.pkcs11.SunPKCS11(in);
                    Security.addProvider(_pk11provider);
                    _p11KeyStore = KeyStore.getInstance("PKCS11", _pk11provider);
                    if (!helper)
                        _name = _pk11provider.getName();
                }
                _p11KeyStore.load(null, pin);
                privateInitialize = true;
            }
        }
    }

    public void load(String in, char[] pin) throws KeyStoreException, NoSuchAlgorithmException,
            IOException, CertificateException, Exception
    {
        ByteArrayInputStream inStream = new ByteArrayInputStream(in.getBytes());
        load(inStream, pin);
    }

    public Enumeration<String> aliases() throws KeyStoreException, Exception
    {

        if (!privateInitialize)
            throw (new Exception("UninitializedKeyStore"));

        return _p11KeyStore.aliases();
    }

    public Certificate getCertificate(String alias) throws KeyStoreException, Exception
    {

        if (!privateInitialize)
            throw (new Exception("UninitializedKeyStore"));

        return _p11KeyStore.getCertificate(alias);
    }

    public Certificate[] getUserCertificates() throws KeyStoreException, Exception
    {
        if (helper)
            return pk11h.getCertificates();
        else
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
    }

    public String getAliasFromCertificate(Certificate cer) throws KeyStoreException
    {
        X509Certificate xcer = (X509Certificate) cer, auxCer = null;
        String auxAlias = null;

        if (privateInitialize)
        {
            Enumeration<String> e = _p11KeyStore.aliases();
            
            while (e.hasMoreElements())
            {
                auxAlias = (String) e.nextElement();
                auxCer = (X509Certificate) _p11KeyStore.getCertificate(auxAlias);
                if ((auxCer.getIssuerDN().equals(xcer.getIssuerDN()))
                        && (auxCer.getSerialNumber().equals(xcer.getSerialNumber())))
                {
                    return auxAlias;
                }
            }

        }

        return null;
    }

    public Key getKey(String alias) throws KeyStoreException, Exception
    {
        return _p11KeyStore.getKey(alias, _pin);
    }

    public Provider getProvider()
    {
        return _pk11provider;
    }

    public void setProvider(Provider provider) throws Exception
    {
        //Does nothing, seems non sense by this time.
    	throw new Exception("Method not implemented");
    }


    public SupportedKeystore getName()
    {
        return SupportedKeystore.PKCS11;
    }

    public String getTokenName()
    {
        return _tokenName;
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
