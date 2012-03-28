package es.uji.security.crypto.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.apache.log4j.Logger;

public class ConfigManager
{
    private static Logger log = Logger.getLogger(ConfigManager.class);

    private static String DEFAULT_CONFIG_FILE = "ujiCrypto.conf";

    private static Properties properties;
    private static ConfigManager instance;

    public static Properties getDefaultProperties()
    {
        Properties prop = new Properties();

        prop.put("DIGIDOC_NOTARY_IMPL",
                "es.uji.security.crypto.openxades.digidoc.factory.BouncyCastleNotaryFactory");
        prop.put("DIGIDOC_FACTORY_IMPL",
                "es.uji.security.crypto.openxades.digidoc.factory.SAXDigiDocFactory");
        prop.put("DIGIDOC_TIMESTAMP_IMPL",
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

    public String getProperty(String key)
    {
        return properties.getProperty(key);
    }

    public String getProperty(String key, String defaultValue)
    {
        String value = properties.getProperty(key);

        if (value != null)
        {
            return value;
        }
        else
        {
            return defaultValue;
        }
    }

    public String getStringProperty(String key, String defaultValue)
    {
        return properties.getProperty(key, defaultValue);
    }

    public int getIntProperty(String key, int defaultValue)
    {
        int intValue = defaultValue;

        try
        {
            intValue = Integer.parseInt(properties.getProperty(key));
        }
        catch (Exception e)
        {
            log.error("Error parsing number: " + key);
        }

        return intValue;
    }

    public void setProperty(String key, String value)
    {
        properties.setProperty(key, value);
    }

    private ConfigManager()
    {
        properties = new Properties();
        properties.putAll(getDefaultProperties());

        try
        {
            properties.load(ConfigManager.class.getClassLoader().getResourceAsStream(
                    DEFAULT_CONFIG_FILE));
        }
        catch (IOException e)
        {
            log.error("Cant not load ujiCrypto.conf file", e);
        }
    }

    public static ConfigManager getInstance()
    {
        if (instance == null)
        {
            instance = new ConfigManager();
        }

        return instance;
    }

    public void loadRemotePropertiesFile(String baseURL)
    {
        log.debug("Trying to retrieve ujiCrypto.conf from server ...");

        try
        {
            URL url = new URL(baseURL + "/" + DEFAULT_CONFIG_FILE);
            URLConnection uc = url.openConnection();
            uc.connect();

            Properties remoteProperties = new Properties();
            remoteProperties.load(uc.getInputStream());

            log.debug("Remote ujiCrypto.conf loaded successfully!!");

            properties.clear();
            properties.putAll(getDefaultProperties());
            properties.putAll(remoteProperties);
        }
        catch (Exception e)
        {
            log.error("Cann't load ujiCrypto.conf from server. WARNING: Bundled local file will be loaded.");
        }
    }
}