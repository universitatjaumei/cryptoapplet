package es.uji.security.crypto;

import java.io.File;

import javax.xml.bind.JAXBException;

import es.uji.security.crypto.config.Configuration;
import es.uji.security.crypto.config.Device;
import es.uji.security.crypto.config.Libraries;

public class DeviceDetector
{
    public static Device getDeviceWithAvailableLibrary() throws JAXBException
    {
        Configuration configuration = ConfigManager.getConfigurationInstance();

        for (Device device : configuration.getDeviceRegistry().getDevices())
        {
            for (String library : getSpecificOSLibraries(device).getLibraries())
            {
                if (libraryExistsInTheFileSystem(library))
                {
                    return device;
                }
            }
        }

        return null;
    }

    private static Libraries getSpecificOSLibraries(Device device)
    {
        Libraries osLibraries = new Libraries();

        if (OperatingSystemUtils.isLinux())
        {
            osLibraries = device.getLinuxLibraries();
        }
        else if (OperatingSystemUtils.isWindowsUpperEqualToNT())
        {
            osLibraries = device.getWindowsLibraries();
        }
        
        return osLibraries;
    }

    private static boolean libraryExistsInTheFileSystem(String library)
    {
        File fileLibrary = new File(library);
        return (fileLibrary.exists());
    }

//    @SuppressWarnings("restriction")
//    public void init()
//    {
//        try
//        {
//            Provider provider = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(this
//                    .toString().getBytes()));
//            Security.addProvider(provider);
//        }
//        catch (Exception e)
//        {
//            log.error("Could not initialize " + getName() + " in slot " + getSlot() + " loading "
//                    + getLibrary());
//        }
//    }
}
