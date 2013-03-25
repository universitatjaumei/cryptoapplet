package es.uji.apps.cryptoapplet.crypto.signature.validate;

import es.uji.apps.cryptoapplet.crypto.exceptions.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.exceptions.EmptyDocumentPassedToVerifyException;
import es.uji.apps.cryptoapplet.crypto.exceptions.SignatureException;

import java.security.Provider;
import java.security.cert.X509Certificate;

public abstract class AbstractSignatureValidator
{
    protected final Provider provider;
    protected final X509Certificate certificate;
    protected final X509Certificate[] caCertificates;

    public AbstractSignatureValidator(X509Certificate certificate, Provider provider)
            throws CertificateNotFoundException
    {
        this(certificate, new X509Certificate[]{}, provider);
    }

    public AbstractSignatureValidator(X509Certificate certificate, X509Certificate[] caCertificates,
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

    protected void checkSignatureOptions(SignatureValidationOptions signatureValidationOptions)
            throws SignatureException
    {
        if (signatureValidationOptions.getOriginalData() == null)
        {
            throw new EmptyDocumentPassedToVerifyException();
        }
    }
}