package es.uji.apps.cryptoapplet.config.model;

import java.util.ArrayList;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.FIELD)
public class Libraries
{
    @XmlElement(name="lib")
    private ArrayList<String> libraries;

    public ArrayList<String> getLibraries()
    {
        return libraries;
    }

    public void setLibraries(ArrayList<String> libraries)
    {
        this.libraries = libraries;
    }
}
