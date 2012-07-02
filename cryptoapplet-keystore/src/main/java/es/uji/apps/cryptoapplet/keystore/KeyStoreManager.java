package es.uji.apps.cryptoapplet.keystore;

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

import org.apache.log4j.Logger;

import es.uji.apps.cryptoapplet.crypto.BrowserType;
import es.uji.apps.cryptoapplet.keystore.mscapi.SunMSCAPIKeyStore;
import es.uji.apps.cryptoapplet.keystore.pkcs11.PKCS11KeyStore;
import es.uji.apps.cryptoapplet.keystore.pkcs11.devices.Firefox;
import es.uji.apps.cryptoapplet.utils.OperatingSystemUtils;

public class KeyStoreManager
{
    private Logger log = Logger.getLogger(KeyStoreManager.class);

    public List<SimpleKeyStore> keystores;
    private BrowserType navigator;

    public KeyStoreManager(BrowserType navigator) throws GeneralSecurityException, IOException
    {
        this.navigator = navigator;
        this.keystores = new ArrayList<SimpleKeyStore>();

        initKeyStores();
    }

    private void initFirefoxStore() throws GeneralSecurityException, IOException
    {
        if (navigator.equals(BrowserType.FIREFOX))
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
    }

    private void initInternetExplorerStore() throws GeneralSecurityException, IOException
    {
        if (navigator.equals(BrowserType.IEXPLORER)
                || (navigator.equals(BrowserType.CHROME) && OperatingSystemUtils
                        .isWindowsUpperEqualToNT()))
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
        initPKCS11();
    }

    private void initPKCS11()
    {
        // TODO
        // if (!Browser.IEXPLORER.equals(navigator))
        // {
        // Device device = Device.getDeviceWithAvailableLibrary();
        //
        // for (int deviceSlot = 0; deviceSlot < 4; deviceSlot++)
        // {
        // device.setSlot(deviceSlot);
        // device.init();
        // }
        // }
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

    public Entry<PrivateKeyEntry, Provider> getPrivateKeyEntryByDN(String certificateDN)
    {
        try
        {
            for (final SimpleKeyStore keystore : keystores)
            {
                for (final String alias : keystore.aliases())
                {
                    final X509Certificate certificate = (X509Certificate) keystore
                            .getCertificate(alias);

                    if (certificateDN.equalsIgnoreCase(certificate.getSubjectDN().toString()))
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
                                    // TODO Auto-generated catch block
                                    e.printStackTrace();
                                }
                                return new PrivateKeyEntry(privateKey,
                                        new X509Certificate[] { certificate });
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