package es.uji.security.crypto;

import java.io.InputStream;

public interface ISignFormatProvider
{

    // public byte[] formatSignature(byte[] toSign, X509Certificate sCer, PrivateKey pk, Provider
    // pv) throws Exception;
    public InputStream formatSignature(SignatureOptions sigOpt) throws Exception;

    public String getError();
}
