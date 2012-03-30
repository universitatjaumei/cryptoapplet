package es.uji.security.keystore.pkcs11;

import java.io.ByteArrayInputStream;
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

import es.uji.security.crypto.config.StreamUtils;
import es.uji.security.keystore.SimpleKeyStore;

public class PKCS11KeyStore implements SimpleKeyStore
{
    private Provider provider;
    private KeyStore keyStore;
    private String password;

    @SuppressWarnings("restriction")
    public void load(InputStream input, String password) throws GeneralSecurityException,
            IOException
    {
        byte[] config = StreamUtils.inputStreamToByteArray(input);
        Provider provider = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(config));
        
        load(input, password, provider);
    }

    public void load(InputStream input, String password, Provider provider)
            throws GeneralSecurityException, IOException
    {
        this.password = password;
        this.provider = provider;

        keyStore = KeyStore.getInstance("PKCS11", provider);
        keyStore.load(input, password.toCharArray());
    }

    public List<String> aliases() throws KeyStoreException
    {
        checkKeyStoreIsLoaded();

        return Collections.list(keyStore.aliases());
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

    public Key getKey(String alias) throws GeneralSecurityException
    {
        checkKeyStoreIsLoaded();

        return keyStore.getKey(alias, password.toCharArray());
    }

    public Key getKey(String alias, String password) throws GeneralSecurityException
    {
        checkKeyStoreIsLoaded();

        return keyStore.getKey(alias, password.toCharArray());
    }

    private void checkKeyStoreIsLoaded()
    {
        if (keyStore == null)
        {
            throw new IllegalStateException("You must load the keystore before using it");
        }
    }

    public Provider getProvider()
    {
        return provider;
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
}
