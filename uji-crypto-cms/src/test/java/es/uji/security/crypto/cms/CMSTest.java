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

import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.crypto.cms.CMSFormatter;
import es.uji.apps.cryptoapplet.crypto.cms.CMSValidator;
import es.uji.apps.cryptoapplet.crypto.junit.BaseCryptoAppletTest;
import es.uji.apps.cryptoapplet.utils.Base64;
import es.uji.apps.cryptoapplet.utils.StreamUtils;
import es.uji.security.crypto.cms.bc.MyCMSSignedDataGenerator;

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

        Formatter signFormatProvider = new CMSFormatter();
        SignatureResult signatureResult = signFormatProvider.format(signatureOptions);

        showErrors(signatureResult, baseDir + "out-cms.bin");

        // Verify

        byte[] signedData = StreamUtils.inputStreamToByteArray(new FileInputStream(baseDir
                + "out-cms.bin"));

        CMSValidator signatureVerifier = new CMSValidator();

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
