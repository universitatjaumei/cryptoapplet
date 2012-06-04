package es.uji.security.crypto;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.text.MessageFormat;

import org.apache.log4j.Logger;

import es.uji.security.crypto.ConfigManager;
import es.uji.security.crypto.OperatingSystemUtils;

public class Device
{
    private Logger log = Logger.getLogger(Device.class);

    private String name;
    private String library;
    private int slot;
    private boolean disableNativePasswordDialog;

    public Device()
    {
    }

    public Device(String name, String library, int slot, boolean disableNativePasswordDialog)
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

    public int getSlot()
    {
        return slot;
    }

    public void setSlot(int slot)
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

    public static Device getDeviceWithAvailableLibrary()
    {
        ConfigManager configManager = ConfigManager.getInstance();

        String deviceList = configManager.getProperty("cryptoapplet.devices");

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

                if (deviceLibrariesList != null)
                {
                    for (String library : deviceLibrariesList.split(","))
                    {
                        File f = new File(library);

                        if (f.exists())
                        {
                            return new Device(deviceName, library, 0, disableNativePasswordDialog);
                        }
                    }
                }
            }
        }

        return null;
    }

    @SuppressWarnings("restriction")
    public void init()
    {
        try
        {
            Provider provider = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(this
                    .toString().getBytes()));
            Security.addProvider(provider);
        }
        catch (Exception e)
        {
            log.error("Could not initialize " + getName() + " in slot " + getSlot() + " loading "
                    + getLibrary());
        }
    }
}