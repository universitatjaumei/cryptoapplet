package es.uji.security.crypto;

import java.util.List;

public interface IDetailInformationGenerator
{
    public List<SignatureDetailInformation> getDetails(byte[] data) throws CryptoCoreException;
}