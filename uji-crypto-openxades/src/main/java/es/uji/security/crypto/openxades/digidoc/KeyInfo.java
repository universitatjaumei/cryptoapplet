/*
 * KeyInfo.java
 * PROJECT: JDigiDoc
 * DESCRIPTION: Digi Doc functions for creating
 *	and reading signed documents. 
 * AUTHOR:  Veiko Sinivee, S|E|B IT Partner Estonia
 *==================================================
 * Copyright (C) AS Sertifitseerimiskeskus
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * GNU Lesser General Public Licence is available at
 * http://www.gnu.org/copyleft/lesser.html
 *==================================================
 */

package es.uji.security.crypto.openxades.digidoc;

import java.io.Serializable;
import java.util.ArrayList;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPublicKey;
import java.math.BigInteger;

import es.uji.security.crypto.openxades.digidoc.utils.ConvertUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Models the KeyInfo block of an XML-DSIG signature. In DigiDoc library the key info allways
 * contains only one subject certificate, e.g. no uplinks and the smaller items like RSA public key
 * modulus and export are not kept separately but calculated online from the signers certificate.
 * That means they are read-only attributes.
 * 
 * @author Veiko Sinivee
 * @version 1.0
 */
public class KeyInfo implements Serializable
{
    /** parent object - Signature ref */
    private Signature m_signature;

    /**
     * Creates new KeyInfo
     */
    public KeyInfo()
    {
        m_signature = null;
    }

    /**
     * Creates new KeyInfo
     * 
     * @param cert
     *            signers certificate
     */
    public KeyInfo(X509Certificate cert) throws DigiDocException
    {
        setSignersCertificate(cert);
    }

    /**
     * Accessor for Signature attribute
     * 
     * @return value of Signature attribute
     */
    public Signature getSignature()
    {
        return m_signature;
    }

    /**
     * Mutator for Signature attribute
     * 
     * @param uprops
     *            value of Signature attribute
     */
    public void setSignature(Signature sig)
    {
        m_signature = sig;
    }

    /**
     * Accessor for signersCert attribute
     * 
     * @return value of signersCert attribute
     */
    public X509Certificate getSignersCertificate()
    {
        X509Certificate cert = null;
        if (m_signature != null)
        {
            CertValue cval = m_signature.getCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
            if (cval != null)
            {
                cert = cval.getCert();
            }
        }
        return cert;
    }

    /**
     * return certificate owners first name
     * 
     * @return certificate owners first name or null
     */
    public String getSubjectFirstName()
    {
        X509Certificate cert = getSignersCertificate();
        if (cert != null)
            return SignedDoc.getSubjectFirstName(cert);
        else
            return null;
    }

    /**
     * return certificate owners subject DN
     * 
     * @return certificate owners subject DN or null
     * 
     */
    public String getSubjectDN()
    {
        X509Certificate cert = getSignersCertificate();
        if (cert != null)
            return cert.getSubjectDN().toString();
        else
            return null;
    }

    /**
     * return certificate owners last name
     * 
     * @return certificate owners last name or null
     */
    public String getSubjectLastName()
    {
        X509Certificate cert = getSignersCertificate();
        if (cert != null)
            return SignedDoc.getSubjectLastName(cert);
        else
            return null;
    }

    /**
     * return certificate owners personal code
     * 
     * @return certificate owners personal code or null
     */
    public String getSubjectPersonalCode()
    {
        X509Certificate cert = getSignersCertificate();
        if (cert != null)
            return SignedDoc.getSubjectPersonalCode(cert);
        else
            return null;
    }

    /**
     * Mutator for signersCert attribute
     * 
     * @param cert
     *            new value for signersCert attribute
     * @throws DigiDocException
     *             for validation errors
     */
    public void setSignersCertificate(X509Certificate cert) throws DigiDocException
    {
        DigiDocException ex = validateSignersCertificate(cert);
        if (ex != null)
            throw ex;
        if (m_signature != null)
        {
            CertValue cval = m_signature.getOrCreateCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
            cval.setCert(cert);
        }
    }

    /**
     * Helper method to validate a signers cert
     * 
     * @param cert
     *            input data
     * @return exception or null for ok
     */
    private DigiDocException validateSignersCertificate(X509Certificate cert)
    {
        DigiDocException ex = null;
        if (cert == null)
            ex = new DigiDocException(DigiDocException.ERR_SIGNERS_CERT,
                    "Signers certificate is required", null);
        return ex;
    }

    /**
     * return the signers certificates key modulus
     * 
     * @return signers certificates key modulus
     */
    public BigInteger getSignerKeyModulus()
    {
        X509Certificate cert = getSignersCertificate();
        if (cert != null)
            return ((RSAPublicKey) cert.getPublicKey()).getModulus();
        else
            return null;
    }

    /**
     * return the signers certificates key exponent
     * 
     * @return signers certificates key exponent
     */
    public BigInteger getSignerKeyExponent()
    {
        X509Certificate cert = getSignersCertificate();
        if (cert != null)
            return ((RSAPublicKey) cert.getPublicKey()).getPublicExponent();
        else
            return null;
    }

    /**
     * Helper method to validate the whole KeyInfo object
     * 
     * @return a possibly empty list of DigiDocException objects
     */
    public ArrayList validate()
    {
        ArrayList errs = new ArrayList();
        DigiDocException ex = null;
        X509Certificate cert = getSignersCertificate();
        if (cert != null)
            ex = validateSignersCertificate(cert);
        if (ex != null)
            errs.add(ex);
        return errs;
    }

    /**
     * Converts the KeyInfo to XML form
     * 
     * @return XML representation of KeyInfo
     */
    public byte[] toXML() throws DigiDocException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try
        {
            bos.write(ConvertUtils.str2data("<KeyInfo>\n"));
            bos.write(ConvertUtils.str2data("<KeyValue>\n<RSAKeyValue>\n<Modulus>"));
            bos.write(ConvertUtils.str2data(Base64Util.encode(getSignerKeyModulus().toByteArray(),
                    64)));
            bos.write(ConvertUtils.str2data("</Modulus>\n<Exponent>"));
            bos.write(ConvertUtils.str2data(Base64Util.encode(getSignerKeyExponent().toByteArray(),
                    64)));
            bos.write(ConvertUtils.str2data("</Exponent>\n</RSAKeyValue>\n</KeyValue>\n"));
            bos.write(ConvertUtils.str2data("<X509Data>"));
            CertValue cval = null;
            if (m_signature != null)
            {
                cval = m_signature.getCertValueOfType(CertValue.CERTVAL_TYPE_SIGNER);
                if (cval != null)
                    bos.write(cval.toXML());
            }
            bos.write(ConvertUtils.str2data("</X509Data>"));
            if (getSubjectDN() != null)
            {
                bos.write(ConvertUtils.str2data("<X509Data><X509SubjectName>"));
                if (m_signature != null)
                {
                    if (cval != null)
                        bos.write(getSubjectDN().getBytes());
                }
                bos.write(ConvertUtils.str2data("</X509SubjectName></X509Data>"));
            }
            bos.write(ConvertUtils.str2data("</KeyInfo>"));
        }
        catch (IOException ex)
        {
            DigiDocException.handleException(ex, DigiDocException.ERR_XML_CONVERT);
        }
        return bos.toByteArray();
    }

    /**
     * return the stringified form of KeyInfo
     * 
     * @return KeyInfo string representation
     */
    public String toString()
    {
        String str = null;
        try
        {
            str = new String(toXML());
        }
        catch (Exception ex)
        {
        }
        return str;
    }
}
