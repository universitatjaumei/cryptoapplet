package es.uji.security.crypto.config;

public class CertificationAuthority
{
    private String id;
    private String commonName;
    private String certificateAlias;
    private RevocationService ocsp;

    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    public String getCommonName()
    {
        return commonName;
    }

    public void setCommonName(String commonName)
    {
        this.commonName = commonName;
    }

    public String getCertificateAlias()
    {
        return certificateAlias;
    }

    public void setCertificateAlias(String certificateAlias)
    {
        this.certificateAlias = certificateAlias;
    }

    public RevocationService getOcsp()
    {
        return ocsp;
    }

    public void setOcsp(RevocationService ocsp)
    {
        this.ocsp = ocsp;
    }
}