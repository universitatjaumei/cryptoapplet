package es.uji.apps.cryptoapplet.crypto.facturae;

import java.security.Provider;
import java.security.cert.X509Certificate;

import es.uji.apps.cryptoapplet.crypto.BaseValidator;
import es.uji.apps.cryptoapplet.crypto.CertificateNotFoundException;
import es.uji.apps.cryptoapplet.crypto.ValidationException;
import es.uji.apps.cryptoapplet.crypto.ValidationOptions;
import es.uji.apps.cryptoapplet.crypto.ValidationResult;
import es.uji.apps.cryptoapplet.crypto.Validator;
import es.uji.apps.cryptoapplet.crypto.xades.XAdESValidator;

public class FacturaeValidator extends BaseValidator implements Validator
{
    public FacturaeValidator(X509Certificate certificate, Provider provider)
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
            Validator validator = new XAdESValidator(certificate, provider);
            return validator.validate(validationOptions);
        }
        catch (Exception e)
        {
            throw new ValidationException(e);
        }
    }
}
