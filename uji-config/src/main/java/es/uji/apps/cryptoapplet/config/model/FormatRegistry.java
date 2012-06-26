package es.uji.apps.cryptoapplet.config.model;

import java.util.ArrayList;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.FIELD)
public class FormatRegistry
{
    @XmlElement(name = "format")
    private ArrayList<Format> formats;

    public ArrayList<Format> getFormats()
    {
        return formats;
    }

    public void setFormats(ArrayList<Format> formats)
    {
        this.formats = formats;
    }

    public Format getFormat(String id)
    {
        for (Format format : formats)
        {
            if (format.getId() != null && id != null && id.equalsIgnoreCase(format.getId()))
            {
                return format;
            }
        }

        return new Format();
    }
}
