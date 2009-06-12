package es.uji.security.keystore;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import es.uji.security.crypto.SupportedKeystore;

public interface IKeyStore
{
    public void load(char[] pin) throws KeyStoreException, NoSuchAlgorithmException, IOException,
            CertificateException, Exception;

    public Enumeration<String> aliases() throws KeyStoreException, Exception;

    public Certificate getCertificate(String alias) throws KeyStoreException, Exception;

    public Certificate[] getUserCertificates() throws KeyStoreException, Exception;

    public Key getKey(String alias) throws KeyStoreException, Exception;

    public String getAliasFromCertificate(Certificate cer) throws Exception;

    public Provider getProvider();

    public SupportedKeystore getName();

    public String getTokenName();

    public byte[] signMessage(byte[] toSign, String alias) throws NoSuchAlgorithmException,
            Exception;

    public void cleanUp();
}
