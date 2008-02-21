package es.uji.dsign.crypto;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public interface ISignFormatProvider
{
	
	public byte[] formatSignature(byte[] toSign, X509Certificate sCer, PrivateKey pk, Provider pv) throws Exception;
	
	public String getError();
}
