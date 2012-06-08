package es.uji.security.crypto.config;

import java.util.ArrayList;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.FIELD)
public class FormatterRegistry
{
    @XmlElement(name = "formatter")
    private ArrayList<Formatter> formatters;

    public ArrayList<Formatter> getFormatters()
    {
        return formatters;
    }

    public void setFormatters(ArrayList<Formatter> formatters)
    {
        this.formatters = formatters;
    }
}
