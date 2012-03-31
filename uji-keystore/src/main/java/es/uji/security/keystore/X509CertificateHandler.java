package es.uji.security.keystore;

import java.security.Provider;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

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
    private List<String> _extKeyUsage;
    private X509Certificate _xcer = null;
    private SimpleKeyStore _iksh = null;

    boolean[] _keyUsage;
    boolean _emailProtection = false;

    private String[] _keyUsageStr = { "digitalSignature", "nonRepudiation", "keyEncipherment",
            "dataEncipherment", "keyAgreement", "keycertSign", "CRLSign", "encipherOnly",
            "decipherOnly", };

    public X509CertificateHandler(X509Certificate xcer, String alias, SimpleKeyStore iksh)
            throws CertificateParsingException
    {
        _iksh = iksh;
        initialize(xcer, alias, _iksh.getProvider());

    }

    public X509CertificateHandler(X509Certificate xcer, String alias, Provider provider)
            throws CertificateParsingException
    {
        _iksh = null;
        initialize(xcer, alias, provider);
    }

    public void initialize(X509Certificate xcer, String alias, Provider provider)
            throws CertificateParsingException
    {
        String auxStr;
        int auxIdx;

        subjectDN = xcer.getSubjectDN().getName();
        issuerDN = xcer.getIssuerDN().getName();
        _keyUsage = xcer.getKeyUsage();
        _extKeyUsage = xcer.getExtendedKeyUsage();
        _xcer = xcer;

        // Get issuer Organization.
        auxStr = "Unknown";

        auxIdx = issuerDN.indexOf("O=");

        if (auxIdx != -1)
        {
            auxStr = issuerDN.substring(auxIdx);
            auxStr = auxStr.replaceFirst("O=", "");
        }
        else
        {
            auxIdx = issuerDN.indexOf("O =");
            if (auxIdx != -1)
            {
                auxStr = issuerDN.substring(auxIdx);
                auxStr = auxStr.replaceFirst("O =", "");
            }
        }

        if (auxStr.indexOf("=") > -1)
        {
            auxStr = auxStr.substring(0, auxStr.indexOf(","));
        }

        auxStr = auxStr.replace('\"', ' ');
        auxStr = auxStr.trim();

        issuerOrganization = auxStr;

        // Get Subject Common Name
        auxStr = subjectDN.substring(subjectDN.indexOf("CN="));
        auxStr = auxStr.replaceFirst("CN=", "");

        if (auxStr.indexOf("=") > -1)
        {
            auxStr = auxStr.substring(0, auxStr.indexOf("=") - 3);
        }

        auxStr = auxStr.replace('\"', ' ');
        auxStr = auxStr.trim();

        auxStr = auxStr.trim();
        if (auxStr.charAt(auxStr.length() - 1) == ',')
        {
            auxStr = auxStr.substring(0, auxStr.length() - 2);
        }

        subjectCN = auxStr;

    }

    public X509Certificate getCertificate()
    {
        return _xcer;
    }

    public String getAlias()
    {
        try
        {
            if (_iksh != null)
                return _iksh.getAliasFromCertificate(_xcer);
        }
        catch (Exception e)
        {

        }
        return null;
    }

    public String getIssuerOrganization()
    {
        return issuerOrganization;
    }

    public String getExtendedInfo()
    {
        String auxStr = "\n  Emitido por:     " + issuerOrganization + "\n";
        auxStr += "  Pertenece a:     " + subjectCN + "\n";
        auxStr += "  Uso de la llave: ";

        // System.out.println("SubjCN: " +auxStr);

        if (_keyUsage != null)
        {

            for (int i = 0; i < _keyUsage.length; i++)
            {
                if (_keyUsage[i])
                {
                    auxStr += _keyUsageStr[i] + ", ";
                }
            }
        }

        if (_extKeyUsage != null)
        {
            for (String u : _extKeyUsage)
            {
                auxStr += u + ", ";
            }
        }

        auxStr = auxStr.substring(0, auxStr.length() - 2);
        auxStr += "\n";

        return auxStr;
    }

    public String getKeyUsage()
    {
        String auxStr = "";

        // System.out.println("Parseando keyUsage...");

        if (_keyUsage != null)
        {

            for (int i = 0; i < _keyUsage.length; i++)
            {
                if (_keyUsage[i])
                {
                    auxStr += _keyUsageStr[i] + ", ";
                    // System.out.println("pillado usage: " + auxStr);
                }
            }
            auxStr = auxStr.substring(0, auxStr.length() - 2);
        }

        if (_extKeyUsage != null)
        {
            for (String u : _extKeyUsage)
            {
                if (u.equals("1.3.6.1.5.5.7.3.2"))
                {
                    _emailProtection = true;
                }
            }
        }

        return auxStr;
    }

    public boolean isEmailProtectionCertificate()
    {
        return _emailProtection;
    }

    public boolean isDigitalSignatureCertificate()
    {
        return (_keyUsage != null && _keyUsage[0]);
    }

    public boolean isNonRepudiationCertificate()
    {
        return (_keyUsage != null && _keyUsage[1]);
    }

    public SimpleKeyStore getKeyStore()
    {
        return _iksh;
    }

    public String toString()
    {
        String kuAux = getKeyUsage();

        if (kuAux.equals(""))
        {
            return subjectCN;
        }
        else
        {
            return subjectCN + " (" + getKeyUsage() + ")";
        }
    }
}