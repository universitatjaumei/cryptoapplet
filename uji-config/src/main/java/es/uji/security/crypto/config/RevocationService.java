package es.uji.security.crypto.config;

public class RevocationService
{
    private String id;
    private String url;
    private String certificateAlias;
    private String caCertificateAlias;
    private Boolean signRequest;
    private Boolean useNonce;

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

    public String getCaCertificateAlias()
    {
        return caCertificateAlias;
    }

    public void setCaCertificateAlias(String caCertificateAlias)
    {
        this.caCertificateAlias = caCertificateAlias;
    }

    public Boolean getSignRequest()
    {
        return signRequest;
    }

    public void setSignRequest(Boolean signRequest)
    {
        this.signRequest = signRequest;
    }

    public Boolean getUseNonce()
    {
        return useNonce;
    }

    public void setUseNonce(Boolean useNonce)
    {
        this.useNonce = useNonce;
    }
}