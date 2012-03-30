package es.uji.security.keystore;

import java.net.ConnectException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.util.Hashtable;

import javax.swing.JOptionPane;

import org.apache.log4j.Logger;

import es.uji.security.crypto.SupportedBrowser;
import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.crypto.config.Device;
import es.uji.security.keystore.clauer.ClauerKeyStore;
import es.uji.security.keystore.mozilla.Mozilla;
import es.uji.security.keystore.mscapi.MSCAPIProvider;
import es.uji.security.keystore.mscapi.MsCapiKeyStore;
import es.uji.security.keystore.pkcs11.PKCS11KeyStore;
import es.uji.security.util.i18n.LabelManager;

public class KeyStoreManager
{
    private Logger log = Logger.getLogger(KeyStoreManager.class);

    public Hashtable<SupportedKeystore, KeyStore> keystores;
    private SupportedBrowser navigator;

    public KeyStoreManager(SupportedBrowser navigator)
    {
        this.navigator = navigator;
        this.keystores = new Hashtable<SupportedKeystore, KeyStore>();
    }

    public void flushKeyStoresTable()
    {
        keystores.clear();
    }

    /*
     * public void initPKCS11Device(Device device, char[] password) throws
     * DeviceInitializationException { byte[] config = device.toString().getBytes();
     * 
     * IKeyStore keystore = null;
     * 
     * try { keystore = (IKeyStore) new PKCS11KeyStore(new ByteArrayInputStream(config), null,
     * false); keystore.load(password);
     * 
     * ArrayList<String> aliases = Collections.list(keystore.aliases());
     * log.debug("Keystore available aliases: " + aliases); } catch (Exception e) {
     * log.debug("Device " + device.getName() +
     * " initialization error. Try to reload the device with the pin");
     * 
     * throw new DeviceInitializationException(e); }
     * 
     * keystores.put(SupportedKeystore.PKCS11, keystore); }
     */

    public void initBrowserStores()
    {
        if (navigator.equals(SupportedBrowser.IEXPLORER))
        {
            IKeyStore keystore = (IKeyStore) new MsCapiKeyStore();

            try
            {
                keystore.load("".toCharArray());
                keystores.put(SupportedKeystore.MSCAPI, keystore);

                Security.addProvider(new MSCAPIProvider());
            }
            catch (Exception ex)
            {
                String error = LabelManager.get("ERR_MS_KEYSTORE_LOAD");

                log.error(error, ex);
                JOptionPane.showMessageDialog(null, ex.getMessage(), error,
                        JOptionPane.WARNING_MESSAGE);
            }
        }
        else if (navigator.equals(SupportedBrowser.MOZILLA))
        {
            try
            {
                Mozilla mozilla = new Mozilla();

                if (mozilla.isInitialized())
                {
                    IKeyStore p11mozillaks = (IKeyStore) new PKCS11KeyStore(
                            mozilla.getPkcs11ConfigInputStream(), mozilla.getPkcs11FilePath(),
                            mozilla.getPkcs11InitArgsString());
                    p11mozillaks.load(null);
                    keystores.put(SupportedKeystore.MOZILLA, p11mozillaks);
                }
                // We have to look here for spanish dnie and ask for the password.
            }
            catch (Exception ex)
            {
                System.out.println("ERR_MOZ_KEYSTORE_LOAD");
                ex.printStackTrace();
            }
        }
    }

    public KeyStore getKeyStore(SupportedKeystore keystore)
    {
        return this.keystores.get(keystore);
    }

    public Hashtable<SupportedKeystore, KeyStore> getKeyStoreTable()
    {
        return this.keystores;
    }

    public void addP12KeyStore(KeyStore keyStore)
    {
        keystores.put(SupportedKeystore.PKCS12, keyStore);
    }

    public void addP11KeyStore(KeyStore keyStore)
    {
        keystores.put(SupportedKeystore.PKCS11, keyStore);
    }

    public void initKeyStores()
    {
        initBrowserStores();
        initPKCS11();

        try
        {
            keyStoreManager.initPKCS11Device(device, null);
        }
        catch (DeviceInitializationException die)
        {
            if (!device.isDisableNativePasswordDialog())
            {
                for (int i = 0; i < 3; i++)
                {
                    PasswordPrompt passwordPrompt = new PasswordPrompt(null, device.getName(),
                            "Pin:");

                    try
                    {
                        this.keyStoreManager.initPKCS11Device(device, passwordPrompt.getPassword());
                        break;
                    }
                    catch (Exception e)
                    {
                        JOptionPane.showMessageDialog(null,
                                LabelManager.get("ERROR_INCORRECT_DNIE_PWD"), "",
                                JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        }
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
}