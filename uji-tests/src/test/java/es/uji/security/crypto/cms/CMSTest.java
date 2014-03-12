package es.uji.security.crypto.cms;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import es.uji.security.BaseCryptoAppletTest;
import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.cms.bc.MyCMSSignedDataGenerator;
import es.uji.security.crypto.config.OS;
import es.uji.security.util.Base64;

public class CMSTest extends BaseCryptoAppletTest
{
    @Before
    public void init()
    {
        signatureOptions.setDataToSign(new ByteArrayInputStream(data));
    }

    @Test
    public void cms() throws Exception
    {
        // Sign

        ISignFormatProvider signFormatProvider = new CMSSignatureFactory();
        SignatureResult signatureResult = signFormatProvider.formatSignature(signatureOptions);

        showErrors(signatureResult, baseDir + "out-cms.bin");

        // Verify

        byte[] signedData = OS.inputStreamToByteArray(new FileInputStream(baseDir + "out-cms.bin"));

        CMSSignatureVerifier signatureVerifier = new CMSSignatureVerifier();

        Assert.assertTrue(signatureVerifier.verify(data, signedData, new X509Certificate[] {},
                provider));
    }

    @Test
    public void mySigneddataGenerator() throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, CertStoreException, CMSException,
            NoSuchProviderException, IOException
    {
        byte[] hash = "01234567890123456789".getBytes();

        MyCMSSignedDataGenerator myCmsSignedDataGenerator = new MyCMSSignedDataGenerator();

        myCmsSignedDataGenerator.addSigner(privateKey, certificate, CMSSignedGenerator.DIGEST_SHA1);

        CMSProcessableByteArray cmsProcessableByteArray = new CMSProcessableByteArray(hash);

        List<Certificate> certList = new ArrayList<Certificate>();
        certList.add(certificate);

        CertStore certStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(certList), provider);
        myCmsSignedDataGenerator.addCertificatesAndCRLs(certStore);
        myCmsSignedDataGenerator.setHash(hash);

        CMSSignedData cmsSignedData = myCmsSignedDataGenerator.generate(cmsProcessableByteArray,
                provider);

        String base64Result = Base64.encodeBytes(cmsSignedData.getEncoded());

        Assert.assertTrue(base64Result != null && base64Result.length() > 0);
    }
}
