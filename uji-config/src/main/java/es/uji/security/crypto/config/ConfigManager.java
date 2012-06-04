package es.uji.security.crypto.config;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ConfigManager
{
    private Keystore keystore;

    private DeviceRegistry devices;
    
    @XmlElement(name = "certificationAuthorities")
    private CertificationAuthorityRegistry certificationAuthoritiesRegistry;
    
    @XmlElement(name = "revocationServices")
    private RevocationServiceRegistry revocationServicesRegistry;
    
    @XmlElement(name = "timestampingServices")
    private TimestampingServiceRegistry timestampingServicesRegistry;

    public Keystore getKeystore()
    {
        return keystore;
    }

    public void setKeystore(Keystore keystore)
    {
        this.keystore = keystore;
    }

    public DeviceRegistry getDevices()
    {
        return devices;
    }

    public void setDevices(DeviceRegistry devices)
    {
        this.devices = devices;
    }

    public CertificationAuthorityRegistry getCertificationAuthoritiesRegistry()
    {
        return certificationAuthoritiesRegistry;
    }

    public void setCertificationAuthoritiesRegistry(
            CertificationAuthorityRegistry certificationAuthoritiesRegistry)
    {
        this.certificationAuthoritiesRegistry = certificationAuthoritiesRegistry;
    }

    public RevocationServiceRegistry getRevocationServicesRegistry()
    {
        return revocationServicesRegistry;
    }

    public void setRevocationServicesRegistry(RevocationServiceRegistry revocationServicesRegistry)
    {
        this.revocationServicesRegistry = revocationServicesRegistry;
    }

    public TimestampingServiceRegistry getTimestampingServicesRegistry()
    {
        return timestampingServicesRegistry;
    }

    public void setTimestampingServicesRegistry(
            TimestampingServiceRegistry timestampingServicesRegistry)
    {
        this.timestampingServicesRegistry = timestampingServicesRegistry;
    }
}