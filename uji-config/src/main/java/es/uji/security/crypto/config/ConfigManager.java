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

    private static ConfigManager instance;    
    private static String DEFAULT_CONFIG_FILE = "ujiCrypto.conf";
    
    private Properties props;    

    private ConfigManager()
    {
        this(DEFAULT_CONFIG_FILE);
    }
        
    private ConfigManager(String configFile)
    {
        if (props == null)
        {
            props = getDefaultProperties();
        }

        // Try to load system properties

        try
        {
            props.load(ConfigManager.class.getClassLoader().getResourceAsStream(configFile));
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

    public static ConfigManager getInstance(String configFile)
    {
        if (instance == null)
        {
            instance = new ConfigManager(configFile);
        }

        return instance;
    }
    
    /**
     * Resets the configuration table
     */

    public void reset()
    {
        props = null;
    }

    /**
     * Reload the configuration table
     */

    public void reload()
    {
        reset();
        instance = new ConfigManager(DEFAULT_CONFIG_FILE);
    }

    public void reload(String configFile)
    {
        reset();
        instance = new ConfigManager(configFile);
    }
    
    /**
     * Retrieves the value for the spcified key
     */

    public String getProperty(String key)
    {
    	System.out.println("ASK FOR: " + key + "return value" + props.getProperty(key));
        return props.getProperty(key);
    }

    /**
     * Retrieves a string value for the spcified key
     */

    public String getStringProperty(String key, String defaultValue)
    {
        return props.getProperty(key, defaultValue);
    }

    /**
     * Retrieves an int value for the spcified key
     */

    public int getIntProperty(String key, int defaultValue)
    {
        int rc = defaultValue;

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
    
    public Properties getProperties()
    {
        return props;
    }
    
    public static Properties getDefaultProperties()
    {
        Properties prop = new Properties();

        prop.put("DIGIDOC_NOTARY_IMPL", "es.uji.security.crypto.openxades.digidoc.factory.BouncyCastleNotaryFactory");
        prop.put("DIGIDOC_FACTORY_IMPL", "es.uji.security.crypto.openxades.digidoc.factory.SAXDigiDocFactory");
        prop.put("DIGIDOC_TIMESTAMP_IMPL", "es.uji.security.crypto.openxades.digidoc.factory.BouncyCastleSignatureTimestampFactory");
        prop.put("CANONICALIZATION_FACTORY_IMPL", "es.uji.security.crypto.openxades.digidoc.factory.DOMCanonicalizationFactory");
        prop.put("CRL_FACTORY_IMPL", "es.uji.security.crypto.openxades.digidoc.factory.CRLCheckerFactory");
        prop.put("DIGIDOC_SECURITY_PROVIDER", "org.bouncycastle.jce.provider.BouncyCastleProvider");
        prop.put("DIGIDOC_SECURITY_PROVIDER_NAME", "BC");
        prop.put("DIGIDOC_VERIFY_ALGORITHM", "RSA//");

        return prop;
    }
    
    public void setProperty(String key, String value)
    {        
        props.setProperty(key, value);
    }
    
    public ArrayList<Device> getDeviceConfig()
    {
    	ConfigManager conf = ConfigManager.getInstance();
    	
    	String deviceList = conf.getProperty("cryptoapplet.devices");
    	ArrayList<Device> result = new ArrayList<Device>();
    	
    	if (deviceList != null)
    	{
    		for (String device : deviceList.split(","))
    		{
    			String deviceName = conf.getProperty("cryptoapplet.devices." + device + ".name");
    			String deviceSlot = conf.getProperty("cryptoapplet.devices." + device + ".slot");
    			
    			String deviceLibrariesList = "";
    			
    			if (OS.isLinux())
    			{
    				deviceLibrariesList = conf.getProperty("cryptoapplet.devices." + device + ".libraries.linux");
    			}
    			else if (OS.isWindowsUpperEqualToNT())
    			{
    				deviceLibrariesList = conf.getProperty("cryptoapplet.devices." + device + ".libraries.windows");            				
    			}

				String deviceLibrary = null;

				for (String library : deviceLibrariesList.split(",")) {
					File f = new File(library);

					if (f.exists()) {
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
					catch  (Exception e)
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