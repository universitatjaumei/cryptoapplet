package es.uji.apps.cryptoapplet.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.log4j.Logger;

import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class ConfigManager
{
    private static Logger log = Logger.getLogger(ConfigManager.class);

    private static String CONFIG_FILE = "conf.xml";

    private static ConfigManager instance;
    private Configuration configuration;

    // TODO
    // public static Properties getDefaultProperties()
    // {
    // Properties prop = new Properties();
    //
    // prop.put("DIGIDOC_NOTARY_IMPL",
    // "es.uji.security.crypto.openxades.digidoc.factory.BouncyCastleNotaryFactory");
    // prop.put("DIGIDOC_FACTORY_IMPL",
    // "es.uji.security.crypto.openxades.digidoc.factory.SAXDigiDocFactory");
    // prop.put("DIGIDOC_TIMESTAMP_IMPL",
    // "es.uji.security.crypto.openxades.digidoc.factory.BouncyCastleSignatureTimestampFactory");
    // prop.put("CANONICALIZATION_FACTORY_IMPL",
    // "es.uji.security.crypto.openxades.digidoc.factory.DOMCanonicalizationFactory");
    // prop.put("CRL_FACTORY_IMPL",
    // "es.uji.security.crypto.openxades.digidoc.factory.CRLCheckerFactory");
    // prop.put("DIGIDOC_SECURITY_PROVIDER", "org.bouncycastle.jce.provider.BouncyCastleProvider");
    // prop.put("DIGIDOC_SECURITY_PROVIDER_NAME", "BC");
    // prop.put("DIGIDOC_VERIFY_ALGORITHM", "RSA//");
    //
    // return prop;
    // }

    private ConfigManager() throws JAXBException
    {
        loadLocalConfigurationFile();
    }

    private ConfigManager(String url) throws JAXBException
    {
        log.debug("Trying to retrieve configuration file from server url: " + url);

        try
        {
            loadRemoteConfigurationFile(url);
            log.debug("Remote config.xml loaded successfully!!");
        }
        catch (Exception e)
        {
            log.error("Cann't load configuration file from server. WARNING: Bundled local file will be loaded.");
            loadLocalConfigurationFile();
        }
    }

    private void loadLocalConfigurationFile() throws JAXBException
    {
        loadXMLFile(ConfigManager.class.getClassLoader().getResourceAsStream(CONFIG_FILE));
    }

    private void loadRemoteConfigurationFile(String url) throws MalformedURLException, IOException,
            JAXBException
    {
        URL configFileUrl = new URL(url);
        byte[] configFile = StreamUtils.inputStreamToByteArray(configFileUrl.openStream());
        loadXMLFile(new ByteArrayInputStream(configFile));
    }

    private void loadXMLFile(InputStream fileReference) throws JAXBException
    {
        JAXBContext context = JAXBContext.newInstance("es.uji.apps.cryptoapplet.config");
        Unmarshaller unmarshaller = context.createUnmarshaller();

        configuration = (Configuration) unmarshaller.unmarshal(fileReference);
    }

    public static Configuration getConfigurationInstance()
    {
        if (instance == null)
        {
            try
            {
                instance = new ConfigManager();
            }
            catch (JAXBException e)
            {
                log.error("Cann't unmarshall " + CONFIG_FILE, e);
                return new Configuration();
            }
        }

        return instance.configuration;
    }

    public static Configuration getConfigurationInstanceFromURL(String url)
    {
        if (instance == null)
        {
            try
            {
                instance = new ConfigManager(url);
            }
            catch (JAXBException e)
            {
                log.error("Cann't unmarshall " + url, e);
                return new Configuration();
            }
        }

        return instance.configuration;
    }
    
    public static void clearConfiguration()
    {       
        instance = null;
    }
}