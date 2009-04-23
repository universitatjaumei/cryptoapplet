package es.uji.dsign.crypto;

import java.security.PrivateKey;

/**
 * 
 * This class represent an abstraction of the private keys stored on the
 * CryptoApi Store.
 * 
 * It has only points to the alias of the certificate whose key we are storing.
 * 
 * @author PSN
 * 
 */

public class MSCAPIPrivateKey implements PrivateKey
{
	private static final long serialVersionUID = 1L;
	private String _alias = null;

	/**
	 * Base Constructor
	 * 
	 * @param alias 
	 * The alias of the certificate corresponding this private key.
	 */
	public MSCAPIPrivateKey(String alias)
	{
		_alias = alias;
	}

	/**
	 * Returns back a representation of the string
	 */
	public String toString()
	{
		return "MSCAPI Private Key Handle";
	}

	public String getAlias()
	{
		return _alias;
	}

	public void setAlias(String alias)
	{
		_alias = alias;
	}

	public String getAlgorithm()
	{
		return "RSA";
	}

	public byte[] getEncoded()
	{
		return null;
	}

	public String getFormat()
	{
		return null;
	}
}
