package es.uji.apps.cryptoapplet.crypto.cms;

import java.io.ByteArrayInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;

import es.uji.apps.cryptoapplet.crypto.BaseFormatter;
import es.uji.apps.cryptoapplet.crypto.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.PrivateKeyNotFoundException;
import es.uji.apps.cryptoapplet.crypto.SignatureException;
import es.uji.apps.cryptoapplet.crypto.SignatureFormatException;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.utils.StreamUtils;
import es.uji.security.crypto.cms.bc.MyCMSSignedDataGenerator;

public class CMSFormatter extends BaseFormatter implements Formatter
{
    public CMSFormatter(X509Certificate certificate, PrivateKey privateKey, Provider provider)
            throws PrivateKeyNotFoundException, CertificateNotFoundException
    {
        super(certificate, privateKey, provider);
    }

    @Override
    public SignatureResult format(SignatureOptions signatureOptions) throws SignatureException
    {
        checkSignatureOptions(signatureOptions);

        byte[] data = StreamUtils.inputStreamToByteArray(signatureOptions.getDataToSign());

        try
        {
            MyCMSSignedDataGenerator formatter = new MyCMSSignedDataGenerator();
            formatter.addSigner(privateKey, certificate, CMSSignedGenerator.DIGEST_SHA1);
            formatter.addCertificatesAndCRLs(generateCertificateStore());

            if (signatureOptions.isHash())
            {
                formatter.setHash(data);
            }

            CMSProcessableByteArray cmsProcessableByteArray = new CMSProcessableByteArray(data);
            CMSSignedData cmsSignedData = formatter.generate(cmsProcessableByteArray, provider);

            if (data == null)
            {
                throw new SignatureFormatException();
            }

            SignatureResult signatureResult = new SignatureResult();
            signatureResult.setValid(true);
            signatureResult.setSignatureData(new ByteArrayInputStream(cmsSignedData.getEncoded()));

            return signatureResult;
        }
        catch (Exception e)
        {
            throw new SignatureException(e);
        }
    }

    private CertStore generateCertificateStore() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException
    {
        List<Certificate> certList = Arrays.asList((Certificate) certificate);
        CertStore certst = CertStore.getInstance("Collection", new CollectionCertStoreParameters(
                certList));
        return certst;
    }
}