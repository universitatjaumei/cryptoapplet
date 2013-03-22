package es.uji.apps.cryptoapplet.keystore;

import es.uji.apps.cryptoapplet.keystore.mscapi.SunMSCAPIKeyStore;
import es.uji.apps.cryptoapplet.keystore.pkcs11.PKCS11KeyStore;
import es.uji.apps.cryptoapplet.keystore.pkcs11.devices.Firefox;
import es.uji.apps.cryptoapplet.utils.OperatingSystemUtils;
import org.apache.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

public class KeyStoreManager
{
    private Logger log = Logger.getLogger(KeyStoreManager.class);

    public List<SimpleKeyStore> keystores;

    public KeyStoreManager() throws GeneralSecurityException, IOException
    {
        this.keystores = new ArrayList<SimpleKeyStore>();

        initKeyStores();
    }

    private void initFirefoxStore() throws GeneralSecurityException, IOException
    {
        log.info("Loading FIREFOX keystore through PKCS11 interface ...");

        Firefox firefox = new Firefox();
        InputStream pkcs11Configuration = new ByteArrayInputStream(
                firefox.getPKCS11Configuration());

        SimpleKeyStore keystore = new PKCS11KeyStore();
        keystore.load(pkcs11Configuration, null);

        log.info("Keystore loaded and added to KeyStoreManager!!");

        keystores.add(keystore);
    }

    private void initInternetExplorerStore() throws GeneralSecurityException, IOException
    {
        if (OperatingSystemUtils.isWindowsUpperEqualToNT())
        {
            SimpleKeyStore keystore = new SunMSCAPIKeyStore();
            keystore.load(null, null);
        }
    }

    public void addKeyStore(SimpleKeyStore keyStore)
    {
        keystores.add(keyStore);
    }

    private void initKeyStores() throws GeneralSecurityException, IOException
    {
        initInternetExplorerStore();
        initFirefoxStore();
    }

    public void flushKeyStoresTable()
    {
        keystores.clear();
    }

    public List<X509Certificate> getCertificates()
    {
        List<X509Certificate> certificates = new ArrayList<X509Certificate>();

        try
        {
            for (SimpleKeyStore keystore : keystores)
            {
                for (String alias : keystore.aliases())
                {
                    certificates.add((X509Certificate) keystore.getCertificate(alias));
                }
            }
        }
        catch (Exception e)
        {
            log.error("Error retrieving certificate list", e);
        }

        return certificates;
    }

    public Entry<PrivateKeyEntry, Provider> getPrivateKeyEntryByDn(String dn)
    {
        try
        {
            for (final SimpleKeyStore keystore : keystores)
            {
                for (final String alias : keystore.aliases())
                {
                    final X509Certificate certificate = (X509Certificate) keystore
                            .getCertificate(alias);

                    if (certificate.getSubjectDN().toString().equalsIgnoreCase(dn))
                    {
                        return new Entry<PrivateKeyEntry, Provider>()
                        {
                            @Override
                            public Provider getValue()
                            {
                                return keystore.getProvider();
                            }

                            @Override
                            public PrivateKeyEntry getKey()
                            {
                                PrivateKey privateKey = null;

                                try
                                {
                                    privateKey = (PrivateKey) keystore.getKey(alias);
                                }
                                catch (GeneralSecurityException e)
                                {
                                    e.printStackTrace();
                                }
                                return new PrivateKeyEntry(privateKey,
                                        new X509Certificate[]{certificate});
                            }

                            @Override
                            public Provider setValue(Provider value)
                            {
                                return null;
                            }
                        };
                    }
                }
            }
        }
        catch (Exception e)
        {
            log.error("Error retrieveing privateKeyByDN", e);
        }

        return null;
    }
}