package es.uji.apps.cryptoapplet.crypto.raw;

import java.security.Provider;
import java.security.Signature;
import java.security.cert.X509Certificate;

import es.uji.apps.cryptoapplet.crypto.BaseValidator;
import es.uji.apps.cryptoapplet.crypto.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.ValidationException;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.utils.StreamUtils;

public class RawValidator extends BaseValidator implements Validator
{
    public RawValidator(X509Certificate certificate, Provider provider)
            throws CertificateNotFoundException
    {
        super(certificate, provider);
    }

    @Override
    public ValidationResult validate(ValidationOptions validationOptions)
            throws ValidationException
    {
        try
        {
            byte[] originalData = StreamUtils.inputStreamToByteArray(validationOptions
                    .getOriginalData());
            byte[] signedData = StreamUtils.inputStreamToByteArray(validationOptions
                    .getSignedData());

            Signature validator = Signature.getInstance("SHA1withRSA", provider);
            validator.initVerify(certificate.getPublicKey());
            validator.update(originalData);

            if (validator.verify(signedData))
            {
                return new ValidationResult(true);
            }

            return new ValidationResult(false);
        }
        catch (Exception e)
        {
            throw new ValidationException(e);
        }
    }
}