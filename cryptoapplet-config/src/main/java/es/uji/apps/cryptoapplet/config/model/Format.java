package es.uji.apps.cryptoapplet.config.model;

import java.util.HashMap;
import java.util.Map;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlAccessorType(XmlAccessType.FIELD)
public class Format
{
    @XmlAttribute(name = "tsa")
    private String tsaId;
    @XmlAttribute
    private String id;
    @XmlJavaTypeAdapter(MapAdapter.class)
    private Map<String, String> configurationOptions;

    public Format()
    {
        configurationOptions = new HashMap<String, String>();
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

    public Map<String, String> getConfigurationOptions()
    {
        return configurationOptions;
    }

    public void setConfigurationOptions(Map<String, String> configurationOptions)
    {
        this.configurationOptions = configurationOptions;
    }
}