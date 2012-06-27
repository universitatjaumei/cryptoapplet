package es.uji.apps.cryptoapplet.keystore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Map.Entry;

import org.apache.log4j.Logger;

import es.uji.apps.cryptoapplet.crypto.BrowserType;
import es.uji.apps.cryptoapplet.crypto.KeystoreType;
import es.uji.apps.cryptoapplet.keystore.mscapi.SunMSCAPIKeyStore;
import es.uji.apps.cryptoapplet.keystore.pkcs11.PKCS11KeyStore;
import es.uji.apps.cryptoapplet.keystore.pkcs11.devices.Firefox;
import es.uji.apps.cryptoapplet.utils.OperatingSystemUtils;

public class KeyStoreManager
{
    private Logger log = Logger.getLogger(KeyStoreManager.class);

    public Hashtable<KeystoreType, SimpleKeyStore> keystores;
    private BrowserType navigator;

    public KeyStoreManager(BrowserType navigator)
    {
        this.navigator = navigator;
        this.keystores = new Hashtable<KeystoreType, SimpleKeyStore>();
    }

    private void initFirefoxStore() throws GeneralSecurityException, IOException
    {
        if (navigator.equals(BrowserType.FIREFOX))
        {
            Firefox firefox = new Firefox();
            InputStream pkcs11Configuration = new ByteArrayInputStream(
                    firefox.getPKCS11Configuration());

            SimpleKeyStore keystore = new PKCS11KeyStore();
            keystore.load(pkcs11Configuration, null);
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

    public SimpleKeyStore getKeyStore(KeystoreType keystore)
    {
        return this.keystores.get(keystore);
    }

    public Hashtable<KeystoreType, SimpleKeyStore> getKeyStoreTable()
    {
        return this.keystores;
    }

    public void addKeyStore(KeystoreType KeystoreType, SimpleKeyStore keyStore)
    {
        keystores.put(KeystoreType, keyStore);
    }

    public void initKeyStores() throws GeneralSecurityException, IOException
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

    public PrivateKeyEntry getPrivateKeyEntryByDN(String certificateDN)
    {
        
        try
        {
            for (Entry<KeystoreType, SimpleKeyStore> keystore : keystores.entrySet())
            {
                SimpleKeyStore simpleKeyStore = keystore.getValue();
                
                for (String alias : keystore.getValue().aliases())
                {
                    X509Certificate certificate = (X509Certificate) simpleKeyStore.getCertificate(alias);

                    if (certificateDN
                            .equalsIgnoreCase(certificate.getSubjectDN().toString()))
                    {
                        PrivateKey privateKey = (PrivateKey) simpleKeyStore.getKey(alias);
                        return new PrivateKeyEntry(privateKey, new X509Certificate[] {certificate});
                    }
                }
            }
        }
        catch (Exception e)
        {
            log.warn(e);
        }

        return null;
    }
}