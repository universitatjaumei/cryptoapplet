package es.uji.apps.cryptoapplet.crypto.signature.format;

import es.uji.apps.cryptoapplet.crypto.exceptions.SignatureException;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidationOptions;

public interface SignatureFormatter
{
    public byte[] format(SignatureOptions signatureOptions) throws SignatureException;
}