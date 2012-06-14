package es.uji.apps.cryptoapplet.crypto.cms;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;

import es.uji.apps.cryptoapplet.config.i18n.LabelManager;
import es.uji.apps.cryptoapplet.crypto.CryptoAppletCoreException;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.utils.StreamUtils;
import es.uji.security.crypto.cms.bc.MyCMSSignedDataGenerator;

public class CMSFormatter implements Formatter
{
    @Override 
    public SignatureResult format(SignatureOptions signatureOptions)
            throws CryptoAppletCoreException
    {
        byte[] data = StreamUtils.inputStreamToByteArray(signatureOptions.getDataToSign());
        X509Certificate certificate = signatureOptions.getCertificate();
        PrivateKey privateKey = signatureOptions.getPrivateKey();
        Provider provider = signatureOptions.getProvider();

        MyCMSSignedDataGenerator gen = new MyCMSSignedDataGenerator();
        SignatureResult signatureResult = new SignatureResult();

        if (certificate == null)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_CMS_NOCERT"));

            return signatureResult;
        }

        if (privateKey == null)
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_CMS_NOKEY"));

            return signatureResult;
        }

        gen.addSigner(privateKey, (X509Certificate) certificate, CMSSignedGenerator.DIGEST_SHA1);
        CMSProcessableByteArray cmsProcessableByteArray = new CMSProcessableByteArray(data);

        List<Certificate> certList = new ArrayList<Certificate>();

        // TODO: Add the intermediate CAs if we have them
        certList.add(certificate);

        try
        {
            CertStore certst = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certList));

            gen.addCertificatesAndCRLs(certst);

            if (signatureOptions.isHash())
            {
                gen.setHash(data);
            }

            CMSSignedData cmsSignedData = gen.generate(cmsProcessableByteArray, provider);

            if (data != null)
            {
                signatureResult.setValid(true);
                signatureResult.setSignatureData(new ByteArrayInputStream(cmsSignedData
                        .getEncoded()));

                return signatureResult;
            }
            else
            {
                signatureResult.setValid(false);
                signatureResult.addError(LabelManager.get("ERROR_CMS_SIGNATURE"));

                return signatureResult;
            }
        }
        catch (Exception e)
        {
            throw new CryptoAppletCoreException(e);
        }
    }
}