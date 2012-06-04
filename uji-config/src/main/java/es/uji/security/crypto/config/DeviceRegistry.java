package es.uji.security.crypto.config;

import java.util.ArrayList;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.FIELD)
public class DeviceRegistry
{
    @XmlElement(name = "device")
    private ArrayList<Device> devices;
    
    public ArrayList<Device> getDevices()
    {
        return devices;
    }

    public void setDevices(ArrayList<Device> devices)
    {
        this.devices = devices;
    }
}