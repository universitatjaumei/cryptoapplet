package es.uji.apps.cryptoapplet.config;

import java.net.URL;
import java.net.URLConnection;
import java.util.Properties;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.log4j.Logger;


public class ConfigManager
{
    private static Logger log = Logger.getLogger(ConfigManager.class);

    private static String CONFIG_FILE = "conf.xml";

    private static ConfigManager instance;

    private Configuration configuration;

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
        JAXBContext context = JAXBContext.newInstance("es.uji.security.crypto.config");
        Unmarshaller unmarshaller = context.createUnmarshaller();
        
        configuration = (Configuration) unmarshaller.unmarshal(ConfigManager.class.getClassLoader()
                .getResourceAsStream(CONFIG_FILE));
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

    public void loadFromRemote(String url)
    {
        log.debug("Trying to retrieve config.xml from server ...");

        try
        {
            URL configFileUrl = new URL(url + "/" + CONFIG_FILE);
            URLConnection uc = configFileUrl.openConnection();
            uc.connect();

            Properties remoteProperties = new Properties();
            remoteProperties.load(uc.getInputStream());

            log.debug("Remote config.xml loaded successfully!!");
        }
        catch (Exception e)
        {
            log.error("Cann't load config.xml from server. WARNING: Bundled local file will be loaded.");
        }
    }
}