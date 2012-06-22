package es.uji.apps.cryptoapplet.crypto;

import java.security.Provider;
import java.security.cert.X509Certificate;

public class BaseValidator
{
    protected final Provider provider;
    protected final X509Certificate certificate;
    protected final X509Certificate[] caCertificates;

    public BaseValidator(X509Certificate certificate, Provider provider)
            throws CertificateNotFoundException
    {
        this(certificate, new X509Certificate[] {}, provider);
    }

    public BaseValidator(X509Certificate certificate, X509Certificate[] caCertificates,
            Provider provider) throws CertificateNotFoundException
    {
        if (certificate == null)
        {
            throw new CertificateNotFoundException();
        }

        this.certificate = certificate;
        this.caCertificates = caCertificates;
        this.provider = provider;
    }

    protected void checkSignatureOptions(ValidationOptions validationOptions)
            throws SignatureException
    {
        if (validationOptions.getOriginalData() == null)
        {
            throw new EmptyDocumentPassedToVerifyException();
        }
    }
}