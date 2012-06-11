package es.uji.apps.cryptoapplet.config;

import java.util.ArrayList;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.FIELD)
public class TimestampingServiceRegistry
{
    @XmlElement(name = "tsa")
    private ArrayList<TimestampingService> timestampingServices;

    public ArrayList<TimestampingService> getTimestampingServices()
    {
        return timestampingServices;
    }

    public void setTimestampingServices(ArrayList<TimestampingService> timestampingServices)
    {
        this.timestampingServices = timestampingServices;
    }
}