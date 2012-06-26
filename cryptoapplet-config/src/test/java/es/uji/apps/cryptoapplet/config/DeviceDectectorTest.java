package es.uji.apps.cryptoapplet.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.config.model.Device;

public class DeviceDectectorTest
{
    @Test
    public void deviceShouldBeRetrievedWhenLibrariesExists() throws Exception
    {
        Configuration configuration = new ConfigurationBuilder().withDeviceRegistry("test",
                "src/test/resources/fakelibrary.ext").build();
        
        DeviceDetector deviceDetector = new DeviceDetector(configuration);
        Device availableDevice = deviceDetector.getDeviceWithAvailableLibrary();

        assertNotNull(availableDevice);
        assertEquals("test", availableDevice.getId());
    }
}