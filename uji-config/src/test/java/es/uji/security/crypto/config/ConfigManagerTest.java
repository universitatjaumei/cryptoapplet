package es.uji.security.crypto.config;

import java.io.FileOutputStream;
import java.util.ArrayList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import org.junit.Test;

public class ConfigManagerTest
{
    @Test
    public void generateBaseConfiguration() throws Exception
    {
        ConfigManager conf = new ConfigManager();
        conf.setKeystore(getKeystore());
        conf.setDevices(getDeviceRegistry());
        conf.setCertificationAuthoritiesRegistry(getCertificationAuthoritiesRegistry());

        JAXBContext context = JAXBContext.newInstance("es.uji.security.crypto.config");
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        marshaller.marshal(conf, new FileOutputStream("target/conf.xml.generated"));
    }

    private Keystore getKeystore()
    {
        Keystore keystore = new Keystore();
        keystore.setId("uji");
        keystore.setType("JKS");
        keystore.setFileName("cas.keystore");
        keystore.setPassword("cryptoapplet");

        return keystore;
    }

    private DeviceRegistry getDeviceRegistry()
    {
        ArrayList<Device> devices = new ArrayList<Device>();
        devices.add(getDeviceDNIe());
        devices.add(getDeviceSermepa());

        DeviceRegistry deviceRegistry = new DeviceRegistry();
        deviceRegistry.setDevices(devices);
        
        return deviceRegistry;
    }

    private Device getDeviceDNIe()
    {
        ArrayList<String> linuxLibraries = new ArrayList<String>();
        linuxLibraries.add("/usr/lib/opensc-pkcs11.so");
        linuxLibraries.add("/usr/local/lib/opensc-pkcs11.so");
        linuxLibraries.add("/lib/opensc-pkcs11.so");
        LinuxLibraries linux = new LinuxLibraries();
        linux.setLibraries(linuxLibraries);

        ArrayList<String> windowsLibraries = new ArrayList<String>();
        windowsLibraries.add("c:\\windows\\system32\\UsrPkcs11.dll");
        WindowsLibraries windows = new WindowsLibraries();
        windows.setLibraries(windowsLibraries);

        Device device = new Device();
        device.setId("dnie");
        device.setLinuxLibraries(linux);
        device.setWindowsLibraries(windows);

        return device;
    }

    private Device getDeviceSermepa()
    {
        ArrayList<String> windowsLibraries = new ArrayList<String>();
        windowsLibraries.add("c:\\windows\\system32\\AdvantisPKCS11.dll");
        WindowsLibraries windows = new WindowsLibraries();
        windows.setLibraries(windowsLibraries);

        Device device = new Device();
        device.setId("sermepa");
        device.setWindowsLibraries(windows);

        return device;
    }
    
    private CertificationAuthorityRegistry getCertificationAuthoritiesRegistry()
    {
        ArrayList<CertificationAuthority> certificationAuthorities = new ArrayList<CertificationAuthority>();
        certificationAuthorities.add(getCARootGVA());
        certificationAuthorities.add(getCACAGVA());
        certificationAuthorities.add(getACCVCA2());
        certificationAuthorities.add(getACDNIE001());
        certificationAuthorities.add(getACDNIE002());
        certificationAuthorities.add(getACDNIE003());
        
        CertificationAuthorityRegistry certificationAuthorityRegistry = new CertificationAuthorityRegistry();
        certificationAuthorityRegistry.setCertificationAuthorities(certificationAuthorities);
        
        return certificationAuthorityRegistry;
    }
    
    private RevocationService getOCSPGVA(String caCertificateAlias)
    {
        RevocationService ocsp = new RevocationService();
        ocsp.setId("ocsp-gva");
        ocsp.setUrl("http://ocsp.accv.es");
        ocsp.setCertificateAlias("ocsp-gva");
        ocsp.setCaCertificateAlias(caCertificateAlias);
        ocsp.setSignRequest(false);
        ocsp.setUseNonce(false);
        
        return ocsp;
    }

    private RevocationService getOCSPDNIe(String caCertificateAlias)
    {
        RevocationService ocsp = new RevocationService();
        ocsp.setId("ocsp-dnie");
        ocsp.setUrl("http://ocsp.dnie.es");
        ocsp.setCertificateAlias("ocsp-dnie");
        ocsp.setCaCertificateAlias(caCertificateAlias);
        ocsp.setSignRequest(false);
        ocsp.setUseNonce(false);
        
        return ocsp;
    }
    
    private CertificationAuthority getCARootGVA()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("root-gva");
        ca.setCommonName("Root CA Generalitat Valenciana");
        ca.setCertificateAlias("root-gva");
        ca.setOcsp(getOCSPGVA("cagva"));
        
        return ca;
    }

    private CertificationAuthority getCACAGVA()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("cagva");
        ca.setCommonName("CAGVA");
        ca.setCertificateAlias("cagva");
        ca.setOcsp(getOCSPGVA("cagva"));
        
        return ca;
    }

    private CertificationAuthority getACCVCA2()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("accv-ca2");
        ca.setCommonName("ACCV-CA2");
        ca.setCertificateAlias("accv-ca2");
        ca.setOcsp(getOCSPGVA("cagva"));
        
        return ca;
    }

    private CertificationAuthority getACDNIE001()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("dnie-001");
        ca.setCommonName("AC DNIE 001");
        ca.setCertificateAlias("dnie-1");
        ca.setOcsp(getOCSPDNIe("dnie-1"));
        
        return ca;
    }

    private CertificationAuthority getACDNIE002()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("dnie-002");
        ca.setCommonName("AC DNIE 002");
        ca.setCertificateAlias("dnie-2");
        ca.setOcsp(getOCSPDNIe("dnie-1"));
        
        return ca;
    }

    private CertificationAuthority getACDNIE003()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("dnie-003");
        ca.setCommonName("AC DNIE 003");
        ca.setCertificateAlias("dnie-3");
        ca.setOcsp(getOCSPDNIe("dnie-1"));
        
        return ca;
    }    
}