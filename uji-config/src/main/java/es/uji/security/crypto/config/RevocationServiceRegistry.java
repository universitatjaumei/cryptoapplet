package es.uji.security.crypto.config;

import java.util.ArrayList;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.FIELD)
public class RevocationServiceRegistry
{
    @XmlElement(name = "revocationService")
    private ArrayList<RevocationService> revocationServices;

    public ArrayList<RevocationService> getRevocationServices()
    {
        return revocationServices;
    }

    public void setRevocationServices(ArrayList<RevocationService> revocationServices)
    {
        this.revocationServices = revocationServices;
    }
}
