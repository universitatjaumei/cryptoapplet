package es.uji.security.crypto.config;

import java.util.Map;

public class Formatter
{
    private String id;
    private TimestampingService tsa;
    private Map<String, String> configuration;

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public TimestampingService getTsa()
    {
        return tsa;
    }

    public void setTsa(TimestampingService tsa)
    {
        this.tsa = tsa;
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