package es.uji.security.crypto.jxades;

import java.util.List;

import es.uji.security.crypto.CryptoCoreException;
import es.uji.security.crypto.IDetailInformationGenerator;
import es.uji.security.crypto.SignatureDetailInformation;

public class JXAdESSignatureDetail implements IDetailInformationGenerator
{
    public List<SignatureDetailInformation> getDetails(byte[] data) throws CryptoCoreException
    {
        return SignatureDetailInformation.getSignatureDetailInformation(data,
                "http://uri.etsi.org/01903/v1.3.2#");
    }
}