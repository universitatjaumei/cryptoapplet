package es.uji.security.crypto.config;


public class Device
{
    private String id;
    private Integer slot;
    private Boolean disableNativePasswordDialog;
    private LinuxLibraries linuxLibraries;
    private WindowsLibraries windowsLibraries;
    private MacOSXLibraries macOSXLibraries;

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public Integer getSlot()
    {
        return slot;
    }

    public void setSlot(Integer slot)
    {
        this.slot = slot;
    }

    public Boolean getDisableNativePasswordDialog()
    {
        return disableNativePasswordDialog;
    }

    public void setDisableNativePasswordDialog(Boolean disableNativePasswordDialog)
    {
        this.disableNativePasswordDialog = disableNativePasswordDialog;
    }

    public LinuxLibraries getLinuxLibraries()
    {
        return linuxLibraries;
    }

    public void setLinuxLibraries(LinuxLibraries linuxLibraries)
    {
        this.linuxLibraries = linuxLibraries;
    }

    public WindowsLibraries getWindowsLibraries()
    {
        return windowsLibraries;
    }

    public void setWindowsLibraries(WindowsLibraries windowsLibraries)
    {
        this.windowsLibraries = windowsLibraries;
    }

    public MacOSXLibraries getMacOSXLibraries()
    {
        return macOSXLibraries;
    }

    public void setMacOSXLibraries(MacOSXLibraries macOSXLibraries)
    {
        this.macOSXLibraries = macOSXLibraries;
    }
}