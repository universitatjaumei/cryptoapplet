package es.uji.security.crypto.config;

import javax.xml.bind.annotation.XmlAccessOrder;
import javax.xml.bind.annotation.XmlAccessorOrder;
import javax.xml.bind.annotation.XmlAttribute;

@XmlAccessorOrder(XmlAccessOrder.ALPHABETICAL)
class MapElements
{
    @XmlAttribute
    public String value;
    @XmlAttribute
    public String key;

    public MapElements()
    {
    }

    public MapElements(String key, String value)
    {
        this.key = key;
        this.value = value;
    }
}