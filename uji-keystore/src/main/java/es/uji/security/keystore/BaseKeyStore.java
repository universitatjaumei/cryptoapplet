package es.uji.security.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public abstract class BaseKeyStore
{
    protected Provider provider;
    protected KeyStore keyStore;
    protected char[] password;

    public List<String> aliases() throws KeyStoreException
    {
        checkKeyStoreIsLoaded();

        return Collections.list(keyStore.aliases());
    }

    public String getAliasFromCertificate(Certificate certificate) throws KeyStoreException
    {
        X509Certificate referenceCertificate = (X509Certificate) certificate;
        Principal issuerDN = referenceCertificate.getIssuerDN();
        BigInteger serialNumber = referenceCertificate.getSerialNumber();

        for (String alias : aliases())
        {
            X509Certificate currentCertificate = (X509Certificate) getCertificate(alias);

            if (currentCertificate.getIssuerDN().equals(issuerDN)
                    && currentCertificate.getSerialNumber().equals(serialNumber))
            {
                return alias;
            }
        }

        return null;
    }

    public Certificate getCertificate(String alias) throws KeyStoreException
    {
        checkKeyStoreIsLoaded();

        return keyStore.getCertificate(alias);
    }

    public List<Certificate> getUserCertificates() throws KeyStoreException
    {
        List<Certificate> certificates = new ArrayList<Certificate>();

        for (String alias : aliases())
        {
            certificates.add(getCertificate(alias));
        }

        return certificates;
    }

    protected void checkKeyStoreIsLoaded()
    {
        if (keyStore == null)
        {
            throw new IllegalStateException("You must load the keystore before using it");
        }
    }

    public Key getKey(String alias) throws GeneralSecurityException
    {
        checkKeyStoreIsLoaded();

        return keyStore.getKey(alias, password);
    }

    public Key getKey(String alias, String password) throws GeneralSecurityException
    {
        checkKeyStoreIsLoaded();

        char[] keyPassword = (password != null) ? password.toCharArray() : null;
        return keyStore.getKey(alias, keyPassword);
    }

    public Provider getProvider()
    {
        return provider;
    }

    public void load(InputStream input, String password) throws GeneralSecurityException,
            IOException
    {
        this.password = (password != null) ? password.toCharArray() : null;
    }
}