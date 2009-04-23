package es.uji.dsign.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.PublicKey;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.SignatureSpi;

import es.uji.dsign.crypto.keystore.MsCapiKeyStore;

/**
 * Signature creation service provider interface for our security provider that
 * deals with cryptApi.
 * 
 * @author PSN
 * 
 */

public class SHA1withRSA extends SignatureSpi
{
	private MsCapiKeyStore _mks = new MsCapiKeyStore();
	private ByteArrayOutputStream buffer;
	private String _alias;

	public SHA1withRSA() throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException
	{
		_alias = null;
		buffer = new ByteArrayOutputStream();

		_mks.load("".toCharArray());
	}

	public SHA1withRSA(Provider provider, String algorithm)
	{
		super();
	}

	public AlgorithmParameters engineGetParameters()
	{
		return null;
	}

	public void engineInitSign(PrivateKey privateKey)
	{
		_alias = ((MSCAPIPrivateKey) privateKey).getAlias();
	}

	public void engineInitSign(PrivateKey privateKey, SecureRandom random)
	{
		// Not Implemented yet. Not necessary.
	}

	public void engineInitVerify(PublicKey publicKey)
	{
		// Not Implemented yet. Not necessary.
	}

	public void engineSetParameter(AlgorithmParameterSpec params)
	{
		// Not Implemented yet. Not necessary.
	}

	public byte[] engineSign()
	{
		byte[] res = null;

		try
		{
			res = _mks.signMessage(buffer.toByteArray(), _alias);
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		return res;
	}

	public int engineSign(byte[] outbuf, int offset, int len)
	{
		// Not Implemented yet. Not necessary.
		return -1;
	}

	public void engineUpdate(byte b)
	{
		// Not Implemented yet. Not necessary.
	}

	public void engineUpdate(byte[] b, int off, int len)
	{
		buffer.write(b, off, len);
	}

	public Object engineGetParameter(String param)
	{
		// Not Implemented yet. Not necessary.
		return null;
	}

	public boolean engineVerify(byte[] sigBytes)
	{
		// Not Implemented yet. Not necessary.
		return false;
	}

	public void engineSetParameter(String param, Object value)
	{
		// Not Implemented yet. Not necessary.
	}
}
