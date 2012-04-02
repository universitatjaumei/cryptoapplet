package es.uji.security.keystore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Hashtable;

import es.uji.security.crypto.SupportedBrowser;
import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.crypto.config.Device;
import es.uji.security.keystore.mscapi.SunMSCAPIKeyStore;
import es.uji.security.keystore.pkcs11.PKCS11KeyStore;
import es.uji.security.keystore.pkcs11.devices.Firefox;

public class KeyStoreManager
{
    public Hashtable<SupportedKeystore, SimpleKeyStore> keystores;
    private SupportedBrowser navigator;

    public KeyStoreManager(SupportedBrowser navigator)
    {
        this.navigator = navigator;
        this.keystores = new Hashtable<SupportedKeystore, SimpleKeyStore>();
    }

    public void initBrowserStores() throws GeneralSecurityException, IOException
    {
        initInternetExplorerStore();
        initFirefoxStore();
    }

    private void initFirefoxStore() throws GeneralSecurityException, IOException
    {
        if (navigator.equals(SupportedBrowser.FIREFOX))
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
        if (navigator.equals(SupportedBrowser.IEXPLORER))
        {
            SimpleKeyStore keystore = new SunMSCAPIKeyStore();
            keystore.load(null, null);
        }
    }

    public SimpleKeyStore getKeyStore(SupportedKeystore keystore)
    {
        return this.keystores.get(keystore);
    }

    public Hashtable<SupportedKeystore, SimpleKeyStore> getKeyStoreTable()
    {
        return this.keystores;
    }

    public void addKeyStore(SupportedKeystore supportedKeystore, SimpleKeyStore keyStore)
    {
        keystores.put(supportedKeystore, keyStore);
    }

    public void initKeyStores() throws GeneralSecurityException, IOException
    {
        initBrowserStores();
        initPKCS11();
    }
    
    private void initPKCS11()
    {
        if (!SupportedBrowser.IEXPLORER.equals(navigator))
        {
            Device device = Device.getDeviceWithAvailableLibrary();

            for (int deviceSlot = 0; deviceSlot < 4; deviceSlot++)
            {
                device.setSlot(deviceSlot);
                device.init();
            }
        }
    }

    public void flushKeyStoresTable()
    {
        keystores.clear();
    }
}