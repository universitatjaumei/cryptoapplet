package es.uji.security.crypto.config;

import java.util.ArrayList;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

@XmlAccessorType(XmlAccessType.FIELD)
public class CertificationAuthorityRegistry
{
    @XmlElement(name = "ca")
    private ArrayList<CertificationAuthority> certificationAuthorities;

    public ArrayList<CertificationAuthority> getCertificationAuthorities()
    {
        return certificationAuthorities;
    }

    public void setCertificationAuthorities(
            ArrayList<CertificationAuthority> certificationAuthorities)
    {
        this.certificationAuthorities = certificationAuthorities;
    }
}