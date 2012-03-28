package es.uji.security.crypto.config;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

public class Device
{
    private static Logger log = Logger.getLogger(Device.class);

    private String name;
    private String library;
    private String slot;
    private boolean disableNativePasswordDialog;

    public Device()
    {
    }

    public Device(String name, String library, String slot, boolean disableNativePasswordDialog)
    {
        this.name = name;
        this.library = library;
        this.slot = slot;
        this.disableNativePasswordDialog = disableNativePasswordDialog;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getLibrary()
    {
        return library;
    }

    public void setLibrary(String library)
    {
        this.library = library;
    }

    public String getSlot()
    {
        return slot;
    }

    public void setSlot(String slot)
    {
        this.slot = slot;
    }

    public boolean isDisableNativePasswordDialog()
    {
        return disableNativePasswordDialog;
    }

    @Override
    public String toString()
    {
        return MessageFormat.format("name = {0}\rlibrary = {1}\r\nslot = {2}\r\n", name, library,
                slot);
    }

    public static List<Device> getDevicesConfig()
    {
        ConfigManager configManager = ConfigManager.getInstance();

        String deviceList = configManager.getProperty("cryptoapplet.devices");
        List<Device> result = new ArrayList<Device>();

        if (deviceList != null)
        {
            for (String device : deviceList.split(","))
            {
                String deviceName = configManager.getProperty("cryptoapplet.devices." + device
                        + ".name");
                String deviceLibrariesList = "";
                boolean disableNativePasswordDialog = false;

                if (OperatingSystemUtils.isLinux())
                {
                    deviceLibrariesList = configManager.getProperty("cryptoapplet.devices."
                            + device + ".libraries.linux");

                    String passwordProperty = configManager.getProperty("cryptoapplet.devices."
                            + device + ".libraries.linux.disableNativePasswordDialog");

                    if (passwordProperty != null && passwordProperty.equals("true"))
                    {
                        disableNativePasswordDialog = true;
                    }
                }
                else if (OperatingSystemUtils.isWindowsUpperEqualToNT())
                {
                    deviceLibrariesList = configManager.getProperty("cryptoapplet.devices."
                            + device + ".libraries.windows");

                    String passwordProperty = configManager.getProperty("cryptoapplet.devices."
                            + device + ".libraries.windows.disableNativePasswordDialog");

                    if (passwordProperty != null && passwordProperty.equals("true"))
                    {
                        disableNativePasswordDialog = true;
                    }
                }

                String deviceLibrary = null;

                // If only one OS is supported we can get null over the other
                if (deviceLibrariesList != null)
                {
                    for (String library : deviceLibrariesList.split(","))
                    {
                        File f = new File(library);

                        if (f.exists())
                        {
                            deviceLibrary = library;
                            break;
                        }
                    }
                }

                if (deviceLibrary != null)
                {
                    outerloop: for (int deviceSlot = 0; deviceSlot < 4; deviceSlot++)
                    {
                        Device newDevice = new Device(deviceName, deviceLibrary,
                                String.valueOf(deviceSlot), disableNativePasswordDialog);

                        for (int i = 0; i < 3; i++)
                        {
                            try
                            {
                                Provider provider = new sun.security.pkcs11.SunPKCS11(
                                        new ByteArrayInputStream(newDevice.toString().getBytes()));
                                Security.addProvider(provider);

                                KeyStore.getInstance("PKCS11", provider);
                                log.info("Added provider " + provider.getName());

                                result.add(newDevice);
                                break outerloop;
                            }
                            catch (Exception e)
                            {
                                log.error("Could not initialize " + newDevice.getName()
                                        + " in slot " + newDevice.getSlot() + " loading "
                                        + newDevice.getLibrary());
                            }
                        }
                    }
                }
            }
        }

        return result;
    }
}