package es.uji.apps.cryptoapplet.crypto.signature.details;

import java.util.List;

import es.uji.apps.cryptoapplet.config.CryptoAppletException;

public interface SignatureDetailsGenerator
{
    public List<SignatureDetails> getDetails(byte[] data) throws CryptoAppletException;
}