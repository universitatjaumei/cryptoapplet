package es.uji.apps.cryptoapplet.crypto.raw;

import es.uji.apps.cryptoapplet.crypto.exceptions.SignatureException;
import es.uji.apps.cryptoapplet.crypto.signature.format.AbstractSignatureFormatter;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureFormatter;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureOptions;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.X509Certificate;

public class RawSignatureFormatter extends AbstractSignatureFormatter implements SignatureFormatter
{
    public RawSignatureFormatter(X509Certificate certificate, PrivateKey privateKey, Provider provider)
            throws SignatureException
    {
        super(certificate, privateKey, provider);
    }

    @Override
    public byte[] format(SignatureOptions signatureOptions) throws SignatureException
    {
        checkSignatureOptions(signatureOptions);

        byte[] data = StreamUtils.inputStreamToByteArray(signatureOptions.getDataToSign());

        try
        {
            Signature rsa = Signature.getInstance("SHA1withRSA", provider);
            rsa.initSign(privateKey);
            rsa.update(data);

            return rsa.sign();
        }
        catch (Exception e)
        {
            throw new SignatureException(e);
        }
    }
}