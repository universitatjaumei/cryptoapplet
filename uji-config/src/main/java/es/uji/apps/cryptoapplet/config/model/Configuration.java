package es.uji.apps.cryptoapplet.config.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;


@XmlRootElement(name = "conf")
@XmlAccessorType(XmlAccessType.FIELD)
public class Configuration
{
    private Keystore keystore;

    @XmlElement(name = "devices")
    private DeviceRegistry deviceRegistry;
    @XmlElement(name = "certificationAuthorities")
    private CertificationAuthorityRegistry certificationAuthoritiesRegistry;
    @XmlElement(name = "revocationServices")
    private RevocationServiceRegistry revocationServicesRegistry;
    @XmlElement(name = "timestamping")
    private TimestampingServiceRegistry timestampingServicesRegistry;
    @XmlElement(name = "formatters")
    private FormatterRegistry formatterRegistry;

    public Keystore getKeystore()
    {
        return keystore;
    }

    public void setKeystore(Keystore keystore)
    {
        this.keystore = keystore;
    }

    public DeviceRegistry getDeviceRegistry()
    {
        return deviceRegistry;
    }

    public void setDeviceRegistry(DeviceRegistry deviceRegistry)
    {
        this.deviceRegistry = deviceRegistry;
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

    public FormatterRegistry getFormatterRegistry()
    {
        return formatterRegistry;
    }

    public void setFormatterRegistry(FormatterRegistry formatterRegistry)
    {
        this.formatterRegistry = formatterRegistry;
    }
}