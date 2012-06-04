package es.uji.security.crypto.config;

import java.util.ArrayList;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.FIELD)
public class WindowsLibraries
{
    @XmlElement(name="library")
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
