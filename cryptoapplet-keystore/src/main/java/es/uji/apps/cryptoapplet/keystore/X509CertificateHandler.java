package es.uji.apps.cryptoapplet.keystore;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;

/**
 * keyUsage is a boolean array where positions are:
 * 
 * digitalSignature a[0] nonRepudiation a[1] keyEncipherment a[2] dataEncipherment a[3] keyAgreement
 * a[4] keycertSign a[5] CRLSign a[6] encipherOnly a[7] decipherOnly a[8]
 */

public class X509CertificateHandler
{
    private String subjectDN;
    private String subjectCN;
    private String issuerDN;
    private String issuerOrganization;
    private List<String> extensionKeyUsages;
    private X509Certificate certificate;

    boolean[] keyUsages;
    boolean emailProtection = false;

    private String[] keyUsageDescription = { "digitalSignature", "nonRepudiation",
            "keyEncipherment", "dataEncipherment", "keyAgreement", "keycertSign", "CRLSign",
            "encipherOnly", "decipherOnly", };

    public X509CertificateHandler(X509Certificate certificate) throws CertificateParsingException,
            CertificateEncodingException
    {
        this.certificate = certificate;

        subjectDN = certificate.getSubjectDN().getName();
        issuerDN = certificate.getIssuerDN().getName();
        keyUsages = certificate.getKeyUsage();
        extensionKeyUsages = certificate.getExtendedKeyUsage();

        X509Principal principal = PrincipalUtil.getSubjectX509Principal(certificate);
        issuerOrganization = (String) principal.getValues(X509Name.O).get(0);
        subjectCN = (String) principal.getValues(X509Name.CN).get(0);
    }

    public String getIssuerOrganization()
    {
        return issuerOrganization;
    }

    public String getExtendedInfo()
    {
        StringBuilder result = new StringBuilder();
        
        result.append("Emitido por: ").append(issuerOrganization).append("\n");
        result.append("Pertenece a: ").append(subjectCN).append("\n");
        result.append("Uso de la llave: ");

        for (int i = 0; i < keyUsages.length; i++)
        {
            if (keyUsages[i])
            {
                result.append(keyUsageDescription[i]).append("\n");
            }
        }

        for (String extensionUsage : extensionKeyUsages)
        {
            result.append(extensionUsage).append("\n");
        }

        return result.toString().trim();
    }

    public String getKeyUsage()
    {
        String auxStr = "";

        // System.out.println("Parseando keyUsage...");

        if (keyUsages != null)
        {

            for (int i = 0; i < keyUsages.length; i++)
            {
                if (keyUsages[i])
                {
                    auxStr += keyUsages[i] + ", ";
                    // System.out.println("pillado usage: " + auxStr);
                }
            }
            auxStr = auxStr.substring(0, auxStr.length() - 2);
        }

        if (extensionKeyUsages != null)
        {
            for (String u : extensionKeyUsages)
            {
                if (u.equals("1.3.6.1.5.5.7.3.2"))
                {
                    emailProtection = true;
                }
            }
        }

        return auxStr;
    }

    public boolean isEmailProtectionCertificate()
    {
        return emailProtection;
    }

    public boolean isDigitalSignatureCertificate()
    {
        return (keyUsages != null && keyUsages[0]);
    }

    public boolean isNonRepudiationCertificate()
    {
        return (keyUsages != null && keyUsages[1]);
    }

    public String toString()
    {
        if ("".equals(getKeyUsage()))
        {
            return subjectCN;
        }
        else
        {
            return subjectCN + " (" + getKeyUsage() + ")";
        }
    }
}