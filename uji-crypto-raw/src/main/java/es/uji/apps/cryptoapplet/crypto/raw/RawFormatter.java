package es.uji.apps.cryptoapplet.crypto.raw;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.X509Certificate;

import es.uji.apps.cryptoapplet.crypto.BaseFormatter;
import es.uji.apps.cryptoapplet.crypto.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.Formatter;
import es.uji.apps.cryptoapplet.crypto.PrivateKeyNotFoundException;
import es.uji.apps.cryptoapplet.crypto.SignatureException;
import es.uji.apps.cryptoapplet.crypto.SignatureOptions;
import es.uji.apps.cryptoapplet.crypto.SignatureResult;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class RawFormatter extends BaseFormatter implements Formatter
{
    public RawFormatter(X509Certificate certificate, PrivateKey privateKey, Provider provider)
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
            Signature rsa = Signature.getInstance("SHA1withRSA", provider);
            rsa.initSign(privateKey);
            rsa.update(data);

            byte[] signedData = rsa.sign();

            SignatureResult signatureResult = new SignatureResult(true);
            signatureResult.setSignatureData(new ByteArrayInputStream(signedData));

            return signatureResult;
        }
        catch (Exception e)
        {
            throw new SignatureException(e);
        }
    }
}