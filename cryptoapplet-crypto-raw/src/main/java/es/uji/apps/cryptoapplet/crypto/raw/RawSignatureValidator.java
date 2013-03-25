package es.uji.apps.cryptoapplet.crypto.raw;

import es.uji.apps.cryptoapplet.crypto.exceptions.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.exceptions.ValidationException;
import es.uji.apps.cryptoapplet.crypto.signature.validate.AbstractSignatureValidator;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidationOptions;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidationResult;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidator;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

import java.security.Provider;
import java.security.Signature;
import java.security.cert.X509Certificate;

public class RawSignatureValidator extends AbstractSignatureValidator implements SignatureValidator
{
    public RawSignatureValidator(X509Certificate certificate, Provider provider)
            throws CertificateNotFoundException
    {
        super(certificate, provider);
    }

    @Override
    public SignatureValidationResult validate(SignatureValidationOptions signatureValidationOptions)
            throws ValidationException
    {
        try
        {
            byte[] originalData = StreamUtils.inputStreamToByteArray(signatureValidationOptions
                    .getOriginalData());
            byte[] signedData = StreamUtils.inputStreamToByteArray(signatureValidationOptions
                    .getSignedData());

            Signature validator = Signature.getInstance("SHA1withRSA", provider);
            validator.initVerify(certificate.getPublicKey());
            validator.update(originalData);

            if (validator.verify(signedData))
            {
                return new SignatureValidationResult(true);
            }

            return new SignatureValidationResult(false);
        }
        catch (Exception e)
        {
            throw new ValidationException(e);
        }
    }
}