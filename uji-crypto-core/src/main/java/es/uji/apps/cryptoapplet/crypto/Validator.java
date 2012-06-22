package es.uji.apps.cryptoapplet.crypto;

public interface Validator
{
    public ValidationResult validate(ValidationOptions validationOptions)
            throws ValidationException;
}