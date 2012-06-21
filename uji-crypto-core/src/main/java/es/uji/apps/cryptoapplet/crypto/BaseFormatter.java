package es.uji.apps.cryptoapplet.crypto;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public class BaseFormatter
{
    protected final Provider provider;
    protected final PrivateKey privateKey;
    protected final X509Certificate certificate;

    public BaseFormatter(X509Certificate certificate, PrivateKey privateKey, Provider provider)
            throws PrivateKeyNotFoundException, CertificateNotFoundException
    {
        if (certificate == null)
        {
            throw new CertificateNotFoundException();
        }

        if (privateKey == null)
        {
            throw new PrivateKeyNotFoundException();
        }

        this.certificate = certificate;
        this.privateKey = privateKey;
        this.provider = provider;
    }

    protected void checkSignatureOptions(SignatureOptions signatureOptions)
            throws SignatureException
    {
        if (signatureOptions.getDataToSign() == null)
        {
            throw new EmptyDocumentPassedToSignException();
        }
    }
}