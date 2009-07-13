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
import java.util.Properties;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.cms.bc.MyCMSSignedDataGenerator;
import es.uji.security.crypto.timestamp.TimeStampFactory;
import es.uji.security.util.Base64;
import es.uji.security.util.ConfigHandler;
import es.uji.security.util.OS;
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
            // Now we must check if a timestamp must be calculated
            // reading the configuration file.

            Properties prop = ConfigHandler.getProperties();

            if (prop == null)
            {
                signatureResult.setValid(false);
                signatureResult.addError(LabelManager.get("ERROR_CMS_CONFIG_NOT_FOUND"));

                return signatureResult;
            }

            String doTs = prop.getProperty("CMS_TIMESTAMPING");
            String tsaUrl = prop.getProperty("CMS_TSA_URL");

            if (doTs != null && doTs.toLowerCase().equals("true"))
            {
                byte[] ts = TimeStampFactory.getTimeStamp(tsaUrl, cmsSignedData.getEncoded(), true);

                if (ts == null)
                {
                    log.info("Cannot calculate timestamp from: " + tsaUrl);

                    signatureResult.setValid(false);
                    signatureResult.addError(LabelManager.get("ERROR_CMS_CALCULATING_TS"));

                    return signatureResult;
                }

                signatureResult.setValid(true);
                signatureResult
                        .setSignatureData(new ByteArrayInputStream(
                                ("<data>\r\n  <cms_signature>\r\n"
                                        + new String(Base64
                                                .encode(cmsSignedData.getEncoded(), true))
                                        + "\r\n  </cms_signature>\r\n  <cms_timestamp>\r\n"
                                        + new String(Base64.encode(ts, true)) + "\r\n  </cms_timestamp>\r\n</data>\r\n")
                                        .getBytes()));

                return signatureResult;
            }
            else
            {
                signatureResult.setValid(true);
                signatureResult.setSignatureData(new ByteArrayInputStream(Base64.encode(
                        cmsSignedData.getEncoded(), true)));

                return signatureResult;
            }
        }
        else
        {
            signatureResult.setValid(false);
            signatureResult.addError(LabelManager.get("ERROR_CMS_SIGNATURE"));

            return signatureResult;
        }
    }
}