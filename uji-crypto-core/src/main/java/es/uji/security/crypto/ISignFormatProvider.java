package es.uji.security.crypto;

public interface ISignFormatProvider
{
	
	//public byte[] formatSignature(byte[] toSign, X509Certificate sCer, PrivateKey pk, Provider pv) throws Exception;
	public byte[] formatSignature(SignatureOptions sigOpt) throws Exception;
	
	public String getError();
}
