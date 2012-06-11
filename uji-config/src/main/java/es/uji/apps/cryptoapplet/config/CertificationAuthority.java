package es.uji.apps.cryptoapplet.config;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;

@XmlAccessorType(XmlAccessType.FIELD)
public class CertificationAuthority
{
    @XmlAttribute(name = "ocsp")
    private String ocspId;
    @XmlAttribute
    private String id;
    private String certificateAlias;
    private String commonName;

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

    public String getOcspId()
    {
        if (ocspId != null && !ocspId.isEmpty())
        {
            return ocspId.substring(1);
        }

        return ocspId;
    }

    public void setOcspId(String ocspId)
    {
        this.ocspId = "#" + ocspId;
    }
}