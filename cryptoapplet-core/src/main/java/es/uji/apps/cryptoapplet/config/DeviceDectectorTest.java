package es.uji.apps.cryptoapplet.config;

import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.config.model.Device;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class DeviceDectectorTest
{
    @Test
    public void deviceShouldBeRetrievedWhenLibrariesExists() throws Exception
    {
        Configuration configuration = new ConfigurationBuilder().withDeviceRegistry("test",
                "fakelibrary.ext").build();

        DeviceDetector deviceDetector = new DeviceDetector(configuration);
        Device availableDevice = deviceDetector.getDeviceWithAvailableLibrary();

        assertNotNull(availableDevice);
        assertEquals("test", availableDevice.getId());
    }
}