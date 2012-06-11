package es.uji.apps.cryptoapplet.config;

import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlAccessorType(XmlAccessType.FIELD)
public class Formatter
{
    @XmlAttribute(name = "tsa")
    private String tsaId;
    @XmlAttribute
    private String id;
    @XmlJavaTypeAdapter(MapAdapter.class)
    private Map<String, String> configuration;

    public Formatter()
    {
        configuration = new HashMap<String, String>();
    }

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public String getTsaId()
    {
        if (tsaId != null && !tsaId.isEmpty())
        {
            return tsaId.substring(1);
        }

        return tsaId;
    }

    public void setTsaId(String tsaId)
    {
        this.tsaId = "#" + tsaId;
    }

    public Map<String, String> getConfiguration()
    {
        return configuration;
    }

    public void setConfiguration(Map<String, String> configuration)
    {
        this.configuration = configuration;
    }
}