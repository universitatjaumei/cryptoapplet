package es.uji.security.keystore.pkcs12;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import es.uji.security.keystore.SimpleKeyStore;

public class PKCS12KeyStoreTest
{
    private static final int NUM_CERTIFICATES_IN_STORE = 1;
    private static final String SIGN_CERTIFICATE_ALIAS = "FIRMA";

    @Test(expected = IllegalStateException.class)
    public void shouldGetAndErrorAccessingAliasesIfKeyStoreIsNotLoaded() throws KeyStoreException
    {
        SimpleKeyStore keyStore = new PKCS12KeyStore();
        keyStore.aliases();
    }

    @Test
    public void shouldGetAliasesFromAPKCS12KeyStore() throws FileNotFoundException,
            GeneralSecurityException, IOException
    {
        SimpleKeyStore keyStore = new PKCS12KeyStore();
        keyStore.load(new FileInputStream("src/test/resources/uactivo951v_firma.p12"), "1234");
        List<String> aliases = keyStore.aliases();

        Assert.assertEquals(NUM_CERTIFICATES_IN_STORE, aliases.size());
        Assert.assertEquals(SIGN_CERTIFICATE_ALIAS, aliases.get(0));
    }

    @Test
    public void shouldPKCS12KeyStoreGetAliasFromCertificate() throws FileNotFoundException,
            GeneralSecurityException, IOException
    {
        SimpleKeyStore keyStore = new PKCS12KeyStore();
        keyStore.load(new FileInputStream("src/test/resources/uactivo951v_firma.p12"), "1234");

        Certificate certificate = keyStore.getCertificate(SIGN_CERTIFICATE_ALIAS);

        Assert.assertEquals(SIGN_CERTIFICATE_ALIAS, keyStore.getAliasFromCertificate(certificate));
    }
}