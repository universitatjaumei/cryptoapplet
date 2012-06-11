package es.uji.apps.cryptoapplet.config;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;

@XmlAccessorType(XmlAccessType.FIELD)
public class TimestampingService
{
    @XmlAttribute(name = "ca")
    private String caId;
    @XmlAttribute
    private String id;
    private String url;
    private String certificateAlias;
    private Boolean askCert;
    private Boolean useNonce;
    private Integer sn;
    private Integer timeErrSecs;

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public String getUrl()
    {
        return url;
    }

    public void setUrl(String url)
    {
        this.url = url;
    }

    public String getCertificateAlias()
    {
        return certificateAlias;
    }

    public void setCertificateAlias(String certificateAlias)
    {
        this.certificateAlias = certificateAlias;
    }

    public String getCaId()
    {
        if (caId != null && !caId.isEmpty())
        {
            return caId.substring(1);
        }
        
        return caId;
    }

    public void setCaId(String caId)
    {
        this.caId = "#" + caId;
    }

    public Boolean getAskCert()
    {
        return askCert;
    }

    public void setAskCert(Boolean askCert)
    {
        this.askCert = askCert;
    }

    public Boolean getUseNonce()
    {
        return useNonce;
    }

    public void setUseNonce(Boolean useNonce)
    {
        this.useNonce = useNonce;
    }

    public Integer getSn()
    {
        return sn;
    }

    public void setSn(Integer sn)
    {
        this.sn = sn;
    }

    public Integer getTimeErrSecs()
    {
        return timeErrSecs;
    }

    public void setTimeErrSecs(Integer timeErrSecs)
    {
        this.timeErrSecs = timeErrSecs;
    }
}