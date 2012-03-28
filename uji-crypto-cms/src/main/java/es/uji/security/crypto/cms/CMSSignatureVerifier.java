package es.uji.security.crypto.cms;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

public class CMSSignatureVerifier
{
    private boolean verifyAgainstCA(X509Certificate[] caCertificates, CertStore certs,
            Provider provider) throws CertStoreException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, CertificateException, CertPathValidatorException
    {
        List<Certificate> certChain = new ArrayList<Certificate>();
        
        if (caCertificates.length > 0)
        {
            X509Certificate rootCert = caCertificates[0];
            certChain.add(rootCert);
        }

        for (int i = 1; i < caCertificates.length; i++)
        {
            certChain.add(caCertificates[i]);
        }

        Collection<? extends Certificate> certCollection = certs.getCertificates(null);
        
        for (Certificate c : certCollection)
        {
            certChain.add(c);
        }

        CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(certChain);
        CertStore store = CertStore.getInstance("Collection", ccsp);
        CertPath cp = CertificateFactory.getInstance("X.509", provider).generateCertPath(certChain);

        Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
        trust.add(new TrustAnchor((X509Certificate) certChain.get(0), null));

        PKIXParameters param = new PKIXParameters(trust);
        param.addCertStore(store);
        param.setRevocationEnabled(false);
        param.setTrustAnchors(trust);

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX", provider);
        cpv.validate(cp, param);

        return true;
    }

    /**
     * 
     * Check the signature is correct, conform to plain data and the certificate chain is ok
     * 
     * @throws CertPathValidatorException 
     * @throws CertificateException 
     * @throws InvalidAlgorithmParameterException 
     * 
     */

    @SuppressWarnings("unchecked")
    public boolean verify(byte[] data, byte[] signedData, X509Certificate[] caCertificates,
            Provider provider) throws NoSuchProviderException, NoSuchAlgorithmException, CertStoreException, CMSException, InvalidAlgorithmParameterException, CertificateException, CertPathValidatorException
    {
        CMSProcessableByteArray processableByteArray = new CMSProcessableByteArray(data);

        CMSSignedData cmsSignedData = new CMSSignedData(processableByteArray, signedData);

        CertStore certs = cmsSignedData.getCertificatesAndCRLs("Collection", provider);

        SignerInformationStore signers = cmsSignedData.getSignerInfos();
        Collection<SignerInformation> c = signers.getSigners();

        boolean result = false;

        for (SignerInformation signer : c)
        {
            SignerId signerId = signer.getSID();
            Collection certCollection = certs.getCertificates(signerId);

            Iterator certIt = certCollection.iterator();
            X509Certificate cert = (X509Certificate) certIt.next();
            result = signer.verify(cert, provider);

            if (result)
            {
                result = verifyAgainstCA(caCertificates, certs, provider); 
            }
            else
            {
                return false;
            }
        }

        return result;
    }
}