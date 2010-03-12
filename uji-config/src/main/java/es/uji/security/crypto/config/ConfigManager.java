package es.uji.security.crypto.config;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Properties;

import org.apache.log4j.Logger;

public class ConfigManager
{
    private Logger log = Logger.getLogger(ConfigManager.class);

    private static Properties props = new Properties();
    private static ConfigManager configManager = null;

    private static String DEFAULT_CONFIG_FILE = "ujiCrypto.conf";

    public static ConfigManager getInstance()
    {
        if (configManager == null)
        {
            configManager = new ConfigManager();
        }

        return configManager;
    }

    public static Properties getDefaultProperties()
    {
        Properties prop = new Properties();

        prop.put("DIGIDOC_NOTARY_IMPL",
                "es.uji.security.crypto.openxades.digidoc.factory.BouncyCastleNotaryFactory");
        prop.put("DIGIDOC_FACTORY_IMPL",
                "es.uji.security.crypto.openxades.digidoc.factory.SAXDigiDocFactory");
        prop
                .put("DIGIDOC_TIMESTAMP_IMPL",
                        "es.uji.security.crypto.openxades.digidoc.factory.BouncyCastleSignatureTimestampFactory");
        prop.put("CANONICALIZATION_FACTORY_IMPL",
                "es.uji.security.crypto.openxades.digidoc.factory.DOMCanonicalizationFactory");
        prop.put("CRL_FACTORY_IMPL",
                "es.uji.security.crypto.openxades.digidoc.factory.CRLCheckerFactory");
        prop.put("DIGIDOC_SECURITY_PROVIDER", "org.bouncycastle.jce.provider.BouncyCastleProvider");
        prop.put("DIGIDOC_SECURITY_PROVIDER_NAME", "BC");
        prop.put("DIGIDOC_VERIFY_ALGORITHM", "RSA//");

        return prop;
    }

    private ConfigManager()
    {
        // Try to load system properties

        try
        {
            props.load(ConfigManager.class.getClassLoader()
                    .getResourceAsStream(DEFAULT_CONFIG_FILE));
        }
        catch (IOException e)
        {
            log.error("Cant not load ujiCrypto.conf file", e);
        }

        props.putAll(getDefaultProperties());
    }

    public static String getProperty(String key)
    {
        return props.getProperty(key);
    }

    public static void setProperty(String key, String value)
    {
        props.setProperty(key, value);
    }

    public String getStringProperty(String key, String def)
    {
        return props.getProperty(key, def);
    }

    public int getIntProperty(String key, int def)
    {
        int rc = def;

        try
        {
            rc = Integer.parseInt(props.getProperty(key));
        }
        catch (NumberFormatException ex)
        {
            log.error("Error parsing number: " + key, ex);
        }

        return rc;
    }

    public ArrayList<Device> getDeviceConfig()
    {
        String deviceList = ConfigManager.getProperty("cryptoapplet.devices");
        ArrayList<Device> result = new ArrayList<Device>();

        if (deviceList != null)
        {
            for (String device : deviceList.split(","))
            {
                String deviceName = ConfigManager.getProperty("cryptoapplet.devices." + device
                        + ".name");
                String deviceSlot = ConfigManager.getProperty("cryptoapplet.devices." + device
                        + ".slot");

                String deviceLibrariesList = "";

                if (OS.isLinux())
                {
                    deviceLibrariesList = ConfigManager.getProperty("cryptoapplet.devices."
                            + device + ".libraries.linux");
                }
                else if (OS.isWindowsUpperEqualToNT())
                {
                    deviceLibrariesList = ConfigManager.getProperty("cryptoapplet.devices."
                            + device + ".libraries.windows");
                }

                String deviceLibrary = null;

                for (String library : deviceLibrariesList.split(","))
                {
                    File f = new File(library);

                    if (f.exists())
                    {
                        deviceLibrary = library;
                        break;
                    }
                }

                if (deviceLibrary != null)
                {
                    Device newDevice = new Device(deviceName, deviceLibrary, deviceSlot);

                    try
                    {
                        Provider provider = new sun.security.pkcs11.SunPKCS11(
                                new ByteArrayInputStream(newDevice.toString().getBytes()));
                        Security.addProvider(provider);

                        KeyStore.getInstance("PKCS11", provider);

                        result.add(newDevice);
                    }
                    catch (Exception e)
                    {
                        log.error("Could not initialize " + newDevice.getName() + " in slot "
                                + newDevice.getSlot() + " loading " + newDevice.getLibrary());
                        continue;
                    }
                }
            }
        }

        return result;
    }
}