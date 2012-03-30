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

import es.uji.security.keystore.SimpleKeyStore;
import es.uji.security.keystore.mozilla.Mozilla;

public class PKCS11KeyStoreTest
{
    private static final int NUM_CERTIFICATES_IN_STORE = 2;
    private static final String SIGN_CERTIFICATE_ALIAS = "CIFRADO/c=es,o=generalitat valenciana,ou=pkigva,cn=accv-ca2/8890499274928531747";

    private String getDriverConfiguration()
    {
        Mozilla mozilla = new Mozilla();
        String pkcs11FilePath = "/usr/lib/i386-linux-gnu/nss/libsoftokn3.so";
        String currentprofile = mozilla.getCurrentProfiledir();

        StringBuilder config = new StringBuilder();

        config.append("name=NSS").append("\n");
        config.append("library=").append(pkcs11FilePath).append("\n");
        config.append("attributes=compatibility").append("\n");
        config.append("slot=2").append("\n");
        config.append("nssArgs=\"configdir='").append(currentprofile).append("' ");
        config.append("certPrefix='' keyPrefix='' secmod='secmod.db' flags=readOnly\"");
        config.append("\n");

        return config.toString();
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
        String driverConfiguration = getDriverConfiguration();

        SimpleKeyStore keyStore = new PKCS11KeyStore();
        keyStore.load(new ByteArrayInputStream(driverConfiguration.getBytes()), "");
        List<String> aliases = keyStore.aliases();

        Assert.assertEquals(NUM_CERTIFICATES_IN_STORE, aliases.size());
        Assert.assertEquals(SIGN_CERTIFICATE_ALIAS, aliases.get(0));
    }
    
    @Test
    public void shouldPKCS11KeyStoreGetAliasFromCertificate() throws FileNotFoundException,
            GeneralSecurityException, IOException
    {
        String driverConfiguration = getDriverConfiguration();
        
        SimpleKeyStore keyStore = new PKCS11KeyStore();
        keyStore.load(new ByteArrayInputStream(driverConfiguration.getBytes()), "");

        Certificate certificate = keyStore.getCertificate(SIGN_CERTIFICATE_ALIAS);

        Assert.assertEquals(SIGN_CERTIFICATE_ALIAS, keyStore.getAliasFromCertificate(certificate));
    }
}