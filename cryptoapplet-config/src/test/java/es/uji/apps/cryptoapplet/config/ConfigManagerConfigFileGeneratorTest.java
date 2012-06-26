package es.uji.apps.cryptoapplet.config;

import java.io.FileOutputStream;
import java.util.ArrayList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import org.junit.Test;

import es.uji.apps.cryptoapplet.config.model.CertificationAuthority;
import es.uji.apps.cryptoapplet.config.model.CertificationAuthorityRegistry;
import es.uji.apps.cryptoapplet.config.model.Configuration;
import es.uji.apps.cryptoapplet.config.model.Device;
import es.uji.apps.cryptoapplet.config.model.DeviceRegistry;
import es.uji.apps.cryptoapplet.config.model.Format;
import es.uji.apps.cryptoapplet.config.model.FormatRegistry;
import es.uji.apps.cryptoapplet.config.model.Keystore;
import es.uji.apps.cryptoapplet.config.model.Libraries;
import es.uji.apps.cryptoapplet.config.model.RevocationService;
import es.uji.apps.cryptoapplet.config.model.RevocationServiceRegistry;
import es.uji.apps.cryptoapplet.config.model.TimestampingService;
import es.uji.apps.cryptoapplet.config.model.TimestampingServiceRegistry;

public class ConfigManagerConfigFileGeneratorTest
{
    @Test
    public void generateBaseConfiguration() throws Exception
    {
        Configuration conf = new Configuration();
        conf.setKeystore(getKeystore());
        conf.setDeviceRegistry(getDeviceRegistry());
        conf.setCertificationAuthoritiesRegistry(getCertificationAuthoritiesRegistry());
        conf.setRevocationServicesRegistry(getRevocationServicesRegistry());
        conf.setTimestampingServicesRegistry(getTimestampingServicesRegistry());
        conf.setFormatRegistry(getFormatterRegistry());

        JAXBContext context = JAXBContext.newInstance("es.uji.apps.cryptoapplet.config.model");
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        marshaller.marshal(conf, new FileOutputStream("target/conf.xml"));
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

        Libraries linux = new Libraries();
        linux.setLibraries(linuxLibraries);

        ArrayList<String> windowsLibraries = new ArrayList<String>();
        windowsLibraries.add("c:\\windows\\system32\\UsrPkcs11.dll");
        Libraries windows = new Libraries();
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
        Libraries windows = new Libraries();
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

    private CertificationAuthority getCARootGVA()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("root-gva");
        ca.setCommonName("Root CA Generalitat Valenciana");
        ca.setCertificateAlias("root-gva");
        ca.setOcspId("ocsp-gva");

        return ca;
    }

    private CertificationAuthority getCACAGVA()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("cagva");
        ca.setCommonName("CAGVA");
        ca.setCertificateAlias("cagva");
        ca.setOcspId("ocsp-dnie");

        return ca;
    }

    private CertificationAuthority getACCVCA2()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("accv-ca2");
        ca.setCommonName("ACCV-CA2");
        ca.setCertificateAlias("accv-ca2");
        ca.setOcspId("ocsp-gva");

        return ca;
    }

    private CertificationAuthority getACDNIE001()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("dnie-001");
        ca.setCommonName("AC DNIE 001");
        ca.setCertificateAlias("dnie-1");
        ca.setOcspId("ocsp-dnie");

        return ca;
    }

    private CertificationAuthority getACDNIE002()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("dnie-002");
        ca.setCommonName("AC DNIE 002");
        ca.setCertificateAlias("dnie-2");
        ca.setOcspId("ocsp-dnie");

        return ca;
    }

    private CertificationAuthority getACDNIE003()
    {
        CertificationAuthority ca = new CertificationAuthority();
        ca.setId("dnie-003");
        ca.setCommonName("AC DNIE 003");
        ca.setCertificateAlias("dnie-3");
        ca.setOcspId("ocsp-dnie");

        return ca;
    }

    private RevocationServiceRegistry getRevocationServicesRegistry()
    {
        RevocationServiceRegistry revocationServiceRegistry = new RevocationServiceRegistry();

        ArrayList<RevocationService> revocationServices = new ArrayList<RevocationService>();
        revocationServices.add(getGVARevocationService());
        revocationServices.add(getDNIeRevocationService());

        revocationServiceRegistry.setRevocationServices(revocationServices);

        return revocationServiceRegistry;
    }

    private RevocationService getGVARevocationService()
    {
        RevocationService revocationService = new RevocationService();
        revocationService.setId("ocsp-gva");
        revocationService.setUrl("http://ocsp.accv.es");
        revocationService.setCertificateAlias("ocsp-gva");
        revocationService.setCaId("cagva");
        revocationService.setSignRequest(false);
        revocationService.setUseNonce(false);

        return revocationService;
    }

    private RevocationService getDNIeRevocationService()
    {
        RevocationService revocationService = new RevocationService();
        revocationService.setId("ocsp-dnie");
        revocationService.setUrl("http://ocsp.dnie.es");
        revocationService.setCertificateAlias("ocsp-dnie");
        revocationService.setCaId("dnie-001");
        revocationService.setSignRequest(false);
        revocationService.setUseNonce(false);

        return revocationService;
    }

    private TimestampingServiceRegistry getTimestampingServicesRegistry()
    {
        TimestampingServiceRegistry timestampingServiceRegistry = new TimestampingServiceRegistry();

        ArrayList<TimestampingService> timestampingServices = new ArrayList<TimestampingService>();
        timestampingServices.add(getGVATimestampingService());

        timestampingServiceRegistry.setTimestampingServices(timestampingServices);

        return timestampingServiceRegistry;
    }

    private TimestampingService getGVATimestampingService()
    {
        TimestampingService timestampingService = new TimestampingService();
        timestampingService.setId("tsa-gva");
        timestampingService.setUrl("http://tss.accv.es:8318/tsa");
        timestampingService.setCertificateAlias("tsa1_accv");
        timestampingService.setCaId("cagva");
        timestampingService.setAskCert(false);
        timestampingService.setUseNonce(true);
        timestampingService.setSn(12);
        timestampingService.setTimeErrSecs(60);

        return timestampingService;
    }

    private FormatRegistry getFormatterRegistry()
    {
        FormatRegistry formatterRegistry = new FormatRegistry();

        ArrayList<Format> formats = new ArrayList<Format>();
        formats.add(getPDFFormat());
        formats.add(getCMSFormat());
        formats.add(getXADESFormat());

        formatterRegistry.setFormats(formats);

        return formatterRegistry;
    }

    private Format getXADESFormat()
    {
        Format formatter = new Format();
        formatter.setId("xades");
        formatter.setTsaId("tsa-gva");

        formatter.getConfiguration().put("signerRole", "User");

        return formatter;
    }

    private Format getPDFFormat()
    {
        Format formatter = new Format();
        formatter.setId("pdf");
        formatter.setTsaId("tsa-gva");

        formatter.getConfiguration().put("reason", "CryptoApplet digital signatures");
        formatter.getConfiguration().put("location", "Spain");
        formatter.getConfiguration().put("contact", "Universitat Jaume I");
        
        formatter.getConfiguration().put("signature.visible", "true");
        formatter.getConfiguration().put("signature.type", "GRAPHIC_AND_DESCRIPTION");
        formatter.getConfiguration().put("signature.x", "0");
        formatter.getConfiguration().put("signature.y", "830");
        formatter.getConfiguration().put("signature.x2", "110");
        formatter.getConfiguration().put("signature.y2", "785");
        formatter.getConfiguration().put("signature.page", "1");
        formatter.getConfiguration().put("signature.imgFile", "uji.jpg");
        formatter.getConfiguration().put("signature.textSize", "8");
        formatter.getConfiguration().put("signature.repeatAxis", "X");
        formatter.getConfiguration().put("signature.textPattern", "");

        return formatter;
    }
    
    private Format getCMSFormat()
    {
        Format formatter = new Format();
        formatter.setId("cms");
        formatter.setTsaId("tsa-gva");

        return formatter;
    }    
}