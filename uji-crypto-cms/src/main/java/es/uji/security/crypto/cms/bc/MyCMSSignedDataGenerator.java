package es.uji.security.crypto.cms.bc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * general class for generating a pkcs7-signature message.
 * <p>
 * A simple example of usage.
 * 
 * <pre>
 *      CertStore               certs...
 *      CMSSignedDataGenerator    gen = new CMSSignedDataGenerator();
 *      gen.addSigner(privKey, cert, CMSSignedGenerator.DIGEST_SHA1);
 *      gen.addCertificatesAndCRLs(certs);
 *      CMSSignedData           data = gen.generate(content, &quot;BC&quot;);
 * </pre>
 */
public class MyCMSSignedDataGenerator extends CMSSignedGenerator
{
    List<SignerInf> signerInfs = new ArrayList<SignerInf>();
    byte[] _myhash = null;
    protected Map _digests = new java.util.HashMap();
    protected List _certs = new ArrayList();
    protected List _crls = new ArrayList();
    protected List _signers = new ArrayList();

    public void setHash(byte[] hash)
    {
        _myhash = hash;
    }

    static class DigOutputStream extends OutputStream
    {
        MessageDigest dig;

        public DigOutputStream(MessageDigest dig)
        {
            this.dig = dig;
        }

        public void write(byte[] b, int off, int len) throws IOException
        {
            dig.update(b, off, len);
        }

        public void write(int b) throws IOException
        {
            dig.update((byte) b);
        }
    }

    static class SigOutputStream extends OutputStream
    {
        Signature sig;

        public SigOutputStream(Signature sig)
        {
            this.sig = sig;
        }

        public void write(byte[] b, int off, int len) throws IOException
        {
            try
            {
                sig.update(b, off, len);
            }
            catch (SignatureException e)
            {
                throw new IOException("signature problem: " + e);
            }
        }

        public void write(int b) throws IOException
        {
            try
            {
                sig.update((byte) b);
            }
            catch (SignatureException e)
            {
                throw new IOException("signature problem: " + e);
            }
        }
    }

    private class SignerInf
    {
        PrivateKey key;
        X509Certificate cert;
        String digestOID;
        String encOID;
        CMSAttributeTableGenerator sAttr;
        CMSAttributeTableGenerator unsAttr;
        AttributeTable baseSignedTable;

        SignerInf(PrivateKey key, X509Certificate cert, String digestOID, String encOID)
        {
            this.key = key;
            this.cert = cert;
            this.digestOID = digestOID;
            this.encOID = encOID;
        }

        SignerInf(PrivateKey key, X509Certificate cert, String digestOID, String encOID,
                CMSAttributeTableGenerator sAttr, CMSAttributeTableGenerator unsAttr,
                AttributeTable baseSigneTable)
        {
            this.key = key;
            this.cert = cert;
            this.digestOID = digestOID;
            this.encOID = encOID;
            this.sAttr = sAttr;
            this.unsAttr = unsAttr;
            this.baseSignedTable = baseSigneTable;
        }

        PrivateKey getKey()
        {
            return key;
        }

        X509Certificate getCertificate()
        {
            return cert;
        }

        String getDigestAlgOID()
        {
            return digestOID;
        }

        byte[] getDigestAlgParams()
        {
            return null;
        }

        String getEncryptionAlgOID()
        {
            return encOID;
        }

        CMSAttributeTableGenerator getSignedAttributes()
        {
            return sAttr;
        }

        CMSAttributeTableGenerator getUnsignedAttributes()
        {
            return unsAttr;
        }

        @SuppressWarnings("unchecked")
        SignerInfo toSignerInfo(ASN1ObjectIdentifier contentType, CMSProcessable content,
                Provider sigProvider, boolean addDefaultAttributes) throws IOException,
                SignatureException, InvalidKeyException, NoSuchProviderException,
                NoSuchAlgorithmException, CertificateEncodingException, CMSException
        {
            AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(this
                    .getDigestAlgOID()), DERNull.INSTANCE);
            AlgorithmIdentifier encAlgId = getEncAlgorithmIdentifier(this.getEncryptionAlgOID());
         
            String digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(digestOID);
            String signatureName = digestName + "with"
                    + CMSSignedHelper.INSTANCE.getEncryptionAlgName(encOID);
            
                        
            Signature sig = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, 
                    sigProvider);

            byte[] hash = null;

            if (_myhash == null)
            {
                MessageDigest dig = CMSSignedHelper.INSTANCE.getDigestInstance(digestName,
                        sigProvider);
                if (content != null)
                {
                    content.write(new DigOutputStream(dig));

                    hash = dig.digest();

                    _digests.put(digestOID, hash.clone());
                }
            }
            else
            {
                hash = _myhash;
            }

            AttributeTable signed;

            if (addDefaultAttributes)
            {
                Map parameters = getBaseParameters(contentType, digAlgId, hash);
                signed = (sAttr != null) ? sAttr.getAttributes(Collections
                        .unmodifiableMap(parameters)) : null;
            }
            else
            {
                signed = baseSignedTable;
            }

            ASN1Set signedAttr = getAttributeSet(signed);

            //
            // sig must be composed from the DER encoding.
            //
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            if (signedAttr != null)
            {
                ASN1OutputStream dOut = new ASN1OutputStream(bOut);
                dOut.writeObject(signedAttr);
            }
            else
            {
                content.write(bOut);
            }

            sig.initSign(key);

            sig.update(bOut.toByteArray());

            ASN1OctetString encDigest = new DEROctetString(sig.sign());

            Map parameters = getBaseParameters(contentType, digAlgId, hash);
            parameters.put(CMSAttributeTableGenerator.SIGNATURE, encDigest.getOctets().clone());

            AttributeTable unsigned = (unsAttr != null) ? unsAttr.getAttributes(Collections
                    .unmodifiableMap(parameters)) : null;

            ASN1Set unsignedAttr = getAttributeSet(unsigned);

            X509Certificate cert = this.getCertificate();
            ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getTBSCertificate());
            ASN1InputStream aIn = new ASN1InputStream(bIn);
            TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(aIn.readObject());
            IssuerAndSerialNumber encSid = new IssuerAndSerialNumber(tbs.getIssuer(), tbs
                    .getSerialNumber().getValue());

            return new SignerInfo(new SignerIdentifier(encSid), digAlgId, signedAttr, encAlgId,
                    encDigest, unsignedAttr);
        }
    }

    /**
     * base constructor
     */
    public MyCMSSignedDataGenerator()
    {
    }

    /**
     * add a signer - no attributes other than the default ones will be provided here.
     */
    public void addSigner(PrivateKey key, X509Certificate cert, String digestOID)
            throws IllegalArgumentException
    {
        String encOID = getEncOID(key, digestOID);

        signerInfs.add(new SignerInf(key, cert, digestOID, encOID,
                new DefaultSignedAttributeTableGenerator(), null, null));
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     */
    public void addSigner(PrivateKey key, X509Certificate cert, String digestOID,
            AttributeTable signedAttr, AttributeTable unsignedAttr) throws IllegalArgumentException
    {
        String encOID = getEncOID(key, digestOID);

        signerInfs.add(new SignerInf(key, cert, digestOID, encOID,
                new DefaultSignedAttributeTableGenerator(signedAttr),
                new SimpleAttributeTableGenerator(unsignedAttr), signedAttr));
    }

    /**
     * add a signer with extra signed/unsigned attributes based on generators.
     */
    public void addSigner(PrivateKey key, X509Certificate cert, String digestOID,
            CMSAttributeTableGenerator signedAttrGen, CMSAttributeTableGenerator unsignedAttrGen)
            throws IllegalArgumentException
    {
        String encOID = getEncOID(key, digestOID);

        signerInfs.add(new SignerInf(key, cert, digestOID, encOID, signedAttrGen, unsignedAttrGen,
                null));
    }

    private ASN1Primitive makeObj(byte[] encoding) throws IOException
    {
        if (encoding == null)
        {
            return null;
        }

        ByteArrayInputStream bIn = new ByteArrayInputStream(encoding);
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        return aIn.readObject();
    }

    private AlgorithmIdentifier makeAlgId(String oid, byte[] params) throws IOException
    {
        if (params != null)
        {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid), makeObj(params));
        }
        else
        {
            return new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid), DERNull.INSTANCE);
        }
    }

    private AlgorithmIdentifier getEncAlgorithmIdentifier(String encOid) throws IOException
    {
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(encOid), DERNull.INSTANCE);
    }

    private ASN1Set getAttributeSet(AttributeTable attr)
    {
        if (attr != null)
        {
            return new DERSet(attr.toASN1EncodableVector());
        }
        return null;
    }

    protected String getEncOID(PrivateKey key, String digestOID)
    {
        String encOID = null;

        String keyAlgorithm = key.getAlgorithm();

        if (keyAlgorithm.equals("RSA") || keyAlgorithm.equals("1.2.840.113549.1.1.1"))
        {
            encOID = "1.2.840.113549.1.1.1"; // RSA
        }
        else if (keyAlgorithm.equals("DSA") || keyAlgorithm.equals("1.2.840.10040.4.1"))
        {
            encOID = "1.2.840.10040.4.1"; // DSA
        }
        else if (keyAlgorithm.equals("ECDSA") || keyAlgorithm.equals("EC"))
        {
            encOID = "1.2.840.10045.2.1"; // EC public key
        }
        else if (keyAlgorithm.equals("ECGOST3410"))
        {
            encOID = "1.2.643.2.2.19";
        }
        else if (keyAlgorithm.equals("GOST3410"))
        {
            encOID = "1.2.643.2.2.20";
        }

        return encOID;
    }

    public void addCertificatesAndCRLs(CertStore certStore) throws CertStoreException, CMSException
    {
        _certs.addAll(CMSUtils.getCertificatesFromStore(certStore));
        _crls.addAll(CMSUtils.getCRLsFromStore(certStore));
    }

    /**
     * generate a signed object that for a CMS Signed Data object using the given provider.
     */
    public CMSSignedData generate(CMSProcessable content, Provider sigProvider)
            throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(content, false, sigProvider);
    }

    /**
     * generate a signed object that for a CMS Signed Data object using the given provider - if
     * encapsulate is true a copy of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     */
    public CMSSignedData generate(String signedContentType, CMSProcessable content,
            boolean encapsulate, Provider sigProvider) throws NoSuchAlgorithmException,
            NoSuchProviderException, CMSException
    {
        return generate(signedContentType, content, encapsulate, sigProvider, true);
    }

    /**
     * Similar method to the other generate methods. The additional argument addDefaultAttributes
     * indicates whether or not a default set of signed attributes need to be added automatically.
     * If the argument is set to false, no attributes will get added at all.
     */
    @SuppressWarnings("unchecked")
    public CMSSignedData generate(String signedContentType, CMSProcessable content,
            boolean encapsulate, Provider sigProvider, boolean addDefaultAttributes)
            throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        ASN1EncodableVector digestAlgs = new ASN1EncodableVector();
        ASN1EncodableVector signerInfos = new ASN1EncodableVector();

        ASN1ObjectIdentifier contentTypeOID = new ASN1ObjectIdentifier(signedContentType);

        _digests.clear(); // clear the current preserved digest state

        //
        // add the precalculated SignerInfo objects.
        //
        Iterator it = _signers.iterator();

        while (it.hasNext())
        {
            SignerInformation signer = (SignerInformation) it.next();
            AlgorithmIdentifier digAlgId;

            try
            {
                digAlgId = makeAlgId(signer.getDigestAlgOID(), signer.getDigestAlgParams());
            }
            catch (IOException e)
            {
                throw new CMSException("encoding error.", e);
            }

            digestAlgs.add(digAlgId);

            signerInfos.add(signer.toASN1Structure());
        }

        //
        // add the SignerInfo objects
        //
        it = signerInfs.iterator();

        while (it.hasNext())
        {
            SignerInf signer = (SignerInf) it.next();
            AlgorithmIdentifier digAlgId;

            try
            {
                digAlgId = makeAlgId(signer.getDigestAlgOID(), signer.getDigestAlgParams());

                digestAlgs.add(digAlgId);

                signerInfos.add(signer.toSignerInfo(contentTypeOID, content, sigProvider,
                        addDefaultAttributes));
            }
            catch (IOException e)
            {
                throw new CMSException("encoding error.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CMSException("key inappropriate for signature.", e);
            }
            catch (SignatureException e)
            {
                throw new CMSException("error creating signature.", e);
            }
            catch (CertificateEncodingException e)
            {
                throw new CMSException("error creating sid.", e);
            }
        }

        ASN1Set certificates = null;

        if (_certs.size() != 0)
        {
            certificates = CMSUtils.createBerSetFromList(_certs);
        }

        ASN1Set certrevlist = null;

        if (_crls.size() != 0)
        {
            certrevlist = CMSUtils.createBerSetFromList(_crls);
        }

        ContentInfo encInfo;

        if (encapsulate)
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            try
            {
                content.write(bOut);
            }
            catch (IOException e)
            {
                throw new CMSException("encapsulation error.", e);
            }

            ASN1OctetString octs = new BERConstructedOctetString(bOut.toByteArray());

            encInfo = new ContentInfo(contentTypeOID, octs);
        }
        else
        {
            encInfo = new ContentInfo(contentTypeOID, null);
        }

        SignedData sd = new SignedData(new DERSet(digestAlgs), encInfo, certificates, certrevlist,
                new DERSet(signerInfos));

        ContentInfo contentInfo = new ContentInfo(PKCSObjectIdentifiers.signedData, sd);

        return new CMSSignedData(content, contentInfo);
    }

    /**
     * generate a signed object that for a CMS Signed Data object using the given provider - if
     * encapsulate is true a copy of the message will be included in the signature with the default
     * content type "data".
     */
    public CMSSignedData generate(CMSProcessable content, boolean encapsulate, Provider sigProvider)
            throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return this.generate(DATA, content, encapsulate, sigProvider);
    }
}
