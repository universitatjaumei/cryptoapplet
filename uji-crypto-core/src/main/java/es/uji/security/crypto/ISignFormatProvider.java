package es.uji.security.crypto;

public interface ISignFormatProvider
{
    public SignatureResult formatSignature(SignatureOptions signatureOptions) throws Exception;
}