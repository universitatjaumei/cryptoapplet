package es.uji.apps.cryptoapplet.crypto;

import java.util.List;

public interface DetailInformationGenerator
{
    public List<SignatureDetailInformation> getDetails(byte[] data)
            throws CryptoAppletCoreException;
}