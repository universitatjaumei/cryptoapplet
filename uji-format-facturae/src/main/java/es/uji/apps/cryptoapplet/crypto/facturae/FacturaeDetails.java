package es.uji.apps.cryptoapplet.crypto.facturae;

import java.util.List;

import es.uji.apps.cryptoapplet.crypto.CryptoAppletCoreException;
import es.uji.apps.cryptoapplet.crypto.DetailsGenerator;
import es.uji.apps.cryptoapplet.crypto.SignatureDetails;

public class FacturaeDetails implements DetailsGenerator
{
    public List<SignatureDetails> getDetails(byte[] data) throws CryptoAppletCoreException
    {
        return SignatureDetails.getSignatureDetailInformation(data,
                "http://uri.etsi.org/01903/v1.3.2#");
    }
}