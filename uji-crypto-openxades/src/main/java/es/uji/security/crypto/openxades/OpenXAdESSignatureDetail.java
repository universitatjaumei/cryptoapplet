package es.uji.security.crypto.openxades;

import java.util.List;

import es.uji.security.crypto.CryptoCoreException;
import es.uji.security.crypto.IDetailInformationGenerator;
import es.uji.security.crypto.SignatureDetailInformation;

public class OpenXAdESSignatureDetail implements IDetailInformationGenerator
{
    public List<SignatureDetailInformation> getDetails(byte[] data) throws CryptoCoreException
    {
        return SignatureDetailInformation.getSignatureDetailInformation(data,
                "http://uri.etsi.org/01903/v1.1.1#");
    }
}