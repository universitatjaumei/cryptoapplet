package es.uji.apps.cryptoapplet.config;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import es.uji.apps.cryptoapplet.config.model.Configuration;

public class ConfigManagerTest
{
    @Test
    public void loadConfiguration() throws Exception
    {
        ConfigManager configManager = new ConfigManager();
        Configuration configuration = configManager.getConfiguration();
        
        assertEquals("uji", configuration.getKeystore().getId());
    }
    
    @Test
    public void loadConfigurationFromRemoteFile() throws Exception
    {
        ConfigManager configManager = new ConfigManager(getTestResourcesPath());
        Configuration configuration = configManager.getConfiguration();
        
        assertEquals("uji-test", configuration.getKeystore().getId());
    }
    
    private String getTestResourcesPath()
    {
        String currentPath = this.getClass().getResource("/").getPath();
        currentPath = currentPath.replaceAll("target/test-classes", "src/test/resources/conf-test.xml");

        return "file://" + currentPath;
    }
}