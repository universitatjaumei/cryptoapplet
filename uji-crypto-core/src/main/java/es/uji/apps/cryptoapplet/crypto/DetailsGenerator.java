package es.uji.apps.cryptoapplet.crypto;

import java.util.List;

import es.uji.apps.cryptoapplet.config.CryptoAppletException;

public interface DetailsGenerator
{
    public List<SignatureDetails> getDetails(byte[] data) throws CryptoAppletException;
}