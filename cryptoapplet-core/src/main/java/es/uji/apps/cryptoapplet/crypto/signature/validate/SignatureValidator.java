package es.uji.apps.cryptoapplet.crypto.signature.validate;

import es.uji.apps.cryptoapplet.crypto.exceptions.ValidationException;

public interface SignatureValidator
{
    public SignatureValidationResult validate(SignatureValidationOptions signatureValidationOptions)
            throws ValidationException;
}