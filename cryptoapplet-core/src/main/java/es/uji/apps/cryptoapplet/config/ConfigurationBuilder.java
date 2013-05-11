package es.uji.apps.cryptoapplet.config;

import java.util.ArrayList;

import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.config.model.Device;
import es.uji.apps.cryptoapplet.config.model.DeviceRegistry;
import es.uji.apps.cryptoapplet.config.model.Libraries;

public class ConfigurationBuilder
{
    private Configuration configuration;

    public ConfigurationBuilder()
    {
        configuration = new Configuration();
    }
    
    public ConfigurationBuilder withDeviceRegistry(String deviceId, String libraryPath)
    {
        String currentPath = this.getClass().getResource("/").getPath();
        currentPath = currentPath.replaceAll("target/test-classes", "src/test/resources/");

        Libraries linuxLibraries = new Libraries();
        ArrayList<String> libraries = new ArrayList<String>();
        libraries.add(currentPath + libraryPath);
        linuxLibraries.setLibraries(libraries);
        
        Device device = new Device();
        device.setId(deviceId);
        device.setLinuxLibraries(linuxLibraries);

        ArrayList<Device> devices = new ArrayList<Device>();
        devices.add(device);
        
        DeviceRegistry deviceRegistry = new DeviceRegistry();
        deviceRegistry.setDevices(devices);
        
        configuration.setDeviceRegistry(deviceRegistry);
        
        return this;
    }
    
    public Configuration build()
    {
        return configuration;
    }
}
