package es.uji.security.crypto.config;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.FIELD)
public class Device
{
    @XmlAttribute
    private String id;
    private Integer slot;
    private Boolean disableNativePasswordDialog;    
    @XmlElement(name="linux")
    private Libraries linuxLibraries;
    @XmlElement(name="windows")
    private Libraries windowsLibraries;
    @XmlElement(name="macosx")
    private Libraries macOSXLibraries;

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

    public Libraries getLinuxLibraries()
    {
        return linuxLibraries;
    }

    public void setLinuxLibraries(Libraries linuxLibraries)
    {
        this.linuxLibraries = linuxLibraries;
    }

    public Libraries getWindowsLibraries()
    {
        return windowsLibraries;
    }

    public void setWindowsLibraries(Libraries windowsLibraries)
    {
        this.windowsLibraries = windowsLibraries;
    }

    public Libraries getMacOSXLibraries()
    {
        return macOSXLibraries;
    }

    public void setMacOSXLibraries(Libraries macOSXLibraries)
    {
        this.macOSXLibraries = macOSXLibraries;
    }
}