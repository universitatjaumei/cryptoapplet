package es.uji.security.keystore.pkcs11;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import es.uji.security.keystore.Firefox;
import es.uji.security.keystore.SimpleKeyStore;

public class PKCS11KeyStoreTest
{
    private static final int NUM_CERTIFICATES_IN_STORE = 2;
    private static final String SIGN_CERTIFICATE_ALIAS = "CIFRADO/c=es,o=generalitat valenciana,ou=pkigva,cn=accv-ca2/8890499274928531747";

    private byte[] getDriverConfiguration()
    {
        return new Firefox().getPKCS11Configuration();
    }

    @Test(expected = IllegalStateException.class)
    public void shouldGetAndErrorAccessingAliasesIfKeyStoreIsNotLoaded() throws KeyStoreException
    {
        SimpleKeyStore keyStore = new PKCS11KeyStore();
        keyStore.aliases();
    }

    @Test
    public void shouldGetAliasesFromAPKCS11KeyStore() throws FileNotFoundException,
            GeneralSecurityException, IOException
    {
        byte[] driverConfiguration = getDriverConfiguration();

        SimpleKeyStore keyStore = new PKCS11KeyStore();
        keyStore.load(new ByteArrayInputStream(driverConfiguration), "");
        List<String> aliases = keyStore.aliases();

        Assert.assertEquals(NUM_CERTIFICATES_IN_STORE, aliases.size());
        Assert.assertEquals(SIGN_CERTIFICATE_ALIAS, aliases.get(0));
    }

    @Test
    public void shouldPKCS11KeyStoreGetAliasFromCertificate() throws FileNotFoundException,
            GeneralSecurityException, IOException
    {
        byte[] driverConfiguration = getDriverConfiguration();

        SimpleKeyStore keyStore = new PKCS11KeyStore();
        keyStore.load(new ByteArrayInputStream(driverConfiguration), "");

        Certificate certificate = keyStore.getCertificate(SIGN_CERTIFICATE_ALIAS);

        Assert.assertEquals(SIGN_CERTIFICATE_ALIAS, keyStore.getAliasFromCertificate(certificate));
    }
}