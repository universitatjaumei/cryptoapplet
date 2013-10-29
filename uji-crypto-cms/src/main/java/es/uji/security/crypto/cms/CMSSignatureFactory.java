package es.uji.security.crypto.cms;

import java.io.ByteArrayInputStream;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.cms.bc.MyCMSSignedDataGenerator;
import es.uji.security.crypto.config.OS;
import es.uji.security.util.i18n.LabelManager;

public class CMSSignatureFactory implements ISignFormatProvider
{
    private Logger log = Logger.getLogger(CMSSignatureFactory.class);

    public SignatureResult formatSignature(SignatureOptions signatureOptions)
            throws KeyStoreException, Exception
    {
        byte[] data = OS.inputStreamToByteArray(signatureOptions.getDataToSign());
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

        CertStore certst = CertStore.getInstance("Collection", new CollectionCertStoreParameters(
                certList));

        gen.addCertificatesAndCRLs(certst);

        if (signatureOptions.isHash())
        {
            gen.setHash(data);
        }

        CMSSignedData cmsSignedData = gen.generate(cmsProcessableByteArray, provider);

        if (data != null)
        {
            signatureResult.setValid(true);
            signatureResult.setSignatureData(new ByteArrayInputStream(cmsSignedData.getEncoded()));

            return signatureResult;
        }
        else
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_CMS_SIGNATURE"));

            return signatureResult;
        }
    }
}