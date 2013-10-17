package es.uji.apps.cryptoapplet.ui.webapp.model;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class DataDocument
{
    private Long id;
    private String name;

    public DataDocument()
    {
    }

    public Long getId()
    {
        return id;
    }

    public void setId(Long id)
    {
        this.id = id;
    }

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }
}