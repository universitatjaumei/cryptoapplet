package es.uji.apps.cryptoapplet.config;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

public class ConfigManagerTest
{
    @Before
    public void initConfiguration()
    {
        ConfigManager.clearConfiguration();
    }
    
    @Test
    public void loadConfiguration() throws Exception
    {
        Configuration configuration = ConfigManager.getConfigurationInstance();
        assertEquals("uji", configuration.getKeystore().getId());
    }
    
    @Test
    public void loadConfigurationFromRemoteFile() throws Exception
    {
        String testResourcesPath = getTestResourcesPath();

        Configuration configuration = ConfigManager.getConfigurationInstanceFromURL(testResourcesPath);
        assertEquals("uji-test", configuration.getKeystore().getId());
    }
    
    private String getTestResourcesPath()
    {
        String classPath = System.getProperty("java.class.path");
        String currentPath = classPath.split(":")[0];
        currentPath = currentPath.replaceAll("target/test-classes", "src/test/resources/conf-test.xml");

        return "file://" + currentPath;
    }
}