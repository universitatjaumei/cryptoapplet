package es.uji.apps.cryptoapplet.crypto;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class BaseFormatter
{
    protected final Provider provider;
    protected final PrivateKey privateKey;
    protected final X509Certificate certificate;
    protected final X509Certificate[] caCertificates;

    public BaseFormatter(X509Certificate certificate, PrivateKey privateKey, Provider provider)
            throws PrivateKeyNotFoundException, CertificateNotFoundException,
            CertificateExpiredException
    {
        this(certificate, new X509Certificate[] {}, privateKey, provider);
    }

    public BaseFormatter(X509Certificate certificate, X509Certificate[] caCertificates,
            PrivateKey privateKey, Provider provider) throws CertificateNotFoundException,
            CertificateExpiredException, PrivateKeyNotFoundException
    {
        if (certificate == null)
        {
            throw new CertificateNotFoundException();
        }

        try
        {
            certificate.checkValidity();
        }
        catch (CertificateException cex)
        {
            throw new CertificateExpiredException();
        }

        if (privateKey == null)
        {
            throw new PrivateKeyNotFoundException();
        }

        this.certificate = certificate;
        this.caCertificates = caCertificates;
        this.privateKey = privateKey;
        this.provider = provider;
    }

    protected void checkSignatureOptions(SignatureOptions signatureOptions)
            throws SignatureException, EmptyDocumentPassedToSignException
    {
        if (signatureOptions.getDataToSign() == null)
        {
            throw new EmptyDocumentPassedToSignException();
        }
    }
}