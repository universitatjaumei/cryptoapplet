package es.uji.apps.cryptoapplet.config;

import java.io.File;

import javax.xml.bind.JAXBException;

import es.uji.apps.cryptoapplet.utils.OperatingSystemUtils;

public class DeviceDetector
{
    private final Configuration configuration;

    public DeviceDetector(Configuration configuration)
    {
        this.configuration = configuration;
    }
    
    public Device getDeviceWithAvailableLibrary() throws JAXBException
    {
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

    private Libraries getSpecificOSLibraries(Device device)
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

    private boolean libraryExistsInTheFileSystem(String library)
    {
        File fileLibrary = new File(library);
        return (fileLibrary.exists());
    }

    //TODO
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
