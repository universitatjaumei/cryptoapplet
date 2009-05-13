package es.uji.security.util;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

public class ConfigHandler
{

    private static ConfigHandler config;
    private static Properties prop;
    private static String configFile = "jar://ujiCrypto.conf";

    private ConfigHandler()
    {
        try
        {
            InputStream is;
            prop = new Properties();

            if (configFile.startsWith("jar://"))
            {
                ClassLoader cl = ConfigHandler.class.getClassLoader();
                is = cl.getResourceAsStream(configFile.substring(6));
            }
            else
            {
                is = new FileInputStream(configFile);
            }

            prop.load(is);

            setConstantProperties();
        }
        catch (Exception e)
        {
            e.printStackTrace();
            prop = null;
        }
    }

    private void setConstantProperties()
    {
        // Here we must set some constant properties
        prop.put("DIGIDOC_NOTARY_IMPL", "es.uji.security.crypto.openxades.digidoc.factory.BouncyCastleNotaryFactory");
        prop.put("DIGIDOC_FACTORY_IMPL", "es.uji.security.crypto.openxades.digidoc.factory.SAXDigiDocFactory");
        prop.put("DIGIDOC_TIMESTAMP_IMPL", "es.uji.security.crypto.openxades.digidoc.factory.BouncyCastleSignatureTimestampFactory");
        prop.put("CANONICALIZATION_FACTORY_IMPL", "es.uji.security.crypto.openxades.digidoc.factory.DOMCanonicalizationFactory");
        prop.put("CRL_FACTORY_IMPL", "es.uji.security.crypto.openxades.digidoc.factory.CRLCheckerFactory");
        prop.put("DIGIDOC_SECURITY_PROVIDER", "org.bouncycastle.jce.provider.BouncyCastleProvider");
        prop.put("DIGIDOC_SECURITY_PROVIDER_NAME", "BC");
        prop.put("DIGIDOC_VERIFY_ALGORITHM", "RSA//");
    }

    public static void setConfigFile(String file)
    {
        configFile = file;
    }

    public static String getProperty(String key)
    {

        if (config == null)
            config = new ConfigHandler();

        return prop.getProperty(key);

    }

    public static Properties getProperties()
    {

        if (config == null)
            config = new ConfigHandler();

        return prop;

    }

    public int getIntProperty(String key, int def)
    {

        if (config == null)
            config = new ConfigHandler();

        if (prop.getProperty(key) != null)
            return Integer.parseInt(prop.getProperty(key));

        return def;

    }

}
