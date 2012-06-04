package es.uji.security.crypto.config;

public class TimestampingService
{
    private String id;
    private String url;
    private String certificateAlias;
    private CertificationAuthority ca;
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

    public CertificationAuthority getCa()
    {
        return ca;
    }

    public void setCa(CertificationAuthority ca)
    {
        this.ca = ca;
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