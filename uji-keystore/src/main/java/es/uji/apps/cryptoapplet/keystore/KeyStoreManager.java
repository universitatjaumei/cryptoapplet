package es.uji.apps.cryptoapplet.keystore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Hashtable;

import es.uji.apps.cryptoapplet.crypto.Browser;
import es.uji.apps.cryptoapplet.crypto.KeystoreType;
import es.uji.apps.cryptoapplet.keystore.mscapi.SunMSCAPIKeyStore;
import es.uji.apps.cryptoapplet.keystore.pkcs11.PKCS11KeyStore;
import es.uji.apps.cryptoapplet.keystore.pkcs11.devices.Firefox;

public class KeyStoreManager
{
    public Hashtable<KeystoreType, SimpleKeyStore> keystores;
    private Browser navigator;

    public KeyStoreManager(Browser navigator)
    {
        this.navigator = navigator;
        this.keystores = new Hashtable<KeystoreType, SimpleKeyStore>();
    }

    public void initBrowserStores() throws GeneralSecurityException, IOException
    {
        initInternetExplorerStore();
        initFirefoxStore();
    }

    private void initFirefoxStore() throws GeneralSecurityException, IOException
    {
        if (navigator.equals(Browser.FIREFOX))
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
        if (navigator.equals(Browser.IEXPLORER))
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
        initBrowserStores();
        initPKCS11();
    }

    private void initPKCS11()
    {
        //TODO
//        if (!Browser.IEXPLORER.equals(navigator))
//        {
//            Device device = Device.getDeviceWithAvailableLibrary();
//
//            for (int deviceSlot = 0; deviceSlot < 4; deviceSlot++)
//            {
//                device.setSlot(deviceSlot);
//                device.init();
//            }
//        }
    }

    public void flushKeyStoresTable()
    {
        keystores.clear();
    }
}