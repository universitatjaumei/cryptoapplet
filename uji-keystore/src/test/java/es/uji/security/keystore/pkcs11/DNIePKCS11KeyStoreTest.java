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

import es.uji.apps.cryptoapplet.keystore.SimpleKeyStore;
import es.uji.apps.cryptoapplet.keystore.pkcs11.PKCS11KeyStore;
import es.uji.apps.cryptoapplet.keystore.pkcs11.devices.DNIe;

public class DNIePKCS11KeyStoreTest
{
    // public static void main(String[] args) throws KeyStoreException, ClassNotFoundException,
    // SecurityException, NoSuchMethodException, IllegalArgumentException,
    // InstantiationException, IllegalAccessException, InvocationTargetException
    // {
    // String pkcs11config = "name = DNIE\nlibrary = /usr/lib/opensc-pkcs11.so ";
    // InputStream confStream = new ByteArrayInputStream(pkcs11config.getBytes());
    //
    // Class sunPkcs11Class = Class.forName("sun.security.pkcs11.SunPKCS11");
    // Constructor pkcs11Constr = sunPkcs11Class.getConstructor(InputStream.class);
    //
    // Provider pkcs11Provider = (Provider) pkcs11Constr.newInstance(confStream);
    // Security.addProvider(pkcs11Provider);
    // // KeyStore.getInstance("PKCS11", _pk11provider);
    // //
    // // // Si pasamos de aqui el dnie esta insertado.
    // // Security.removeProvider(_pk11provider.getName());
    // // System.out.println("Saliendo true ...");
    // }

    private static final int NUM_CERTIFICATES_IN_STORE = 2;
    private static final String SIGN_CERTIFICATE_ALIAS = "CertAutenticacion";

    private byte[] getDriverConfiguration()
    {
        return new DNIe().getPKCS11Configuration();
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
        keyStore.load(new ByteArrayInputStream(driverConfiguration), "Heroes2000");
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
        keyStore.load(new ByteArrayInputStream(driverConfiguration), "Heroes2000");

        Certificate certificate = keyStore.getCertificate(SIGN_CERTIFICATE_ALIAS);

        Assert.assertEquals(SIGN_CERTIFICATE_ALIAS, keyStore.getAliasFromCertificate(certificate));
    }
}
