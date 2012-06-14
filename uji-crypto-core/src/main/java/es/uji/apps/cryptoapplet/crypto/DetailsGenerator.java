package es.uji.apps.cryptoapplet.crypto;

import java.util.List;

public interface DetailsGenerator
{
    public List<SignatureDetails> getDetails(byte[] data)
            throws CryptoAppletCoreException;
}