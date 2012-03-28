package es.uji.security.keystore.mscapi;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import es.uji.security.crypto.SupportedKeystore;
import es.uji.security.keystore.IKeyStore;


public class SunMsCapiKeyStore implements IKeyStore
{
	private KeyStore _mscapi;

	public SunMsCapiKeyStore()
	{
		try {
			_mscapi = KeyStore.getInstance("Windows-MY");
			_mscapi.load(null, null);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public String getAliasFromCertificate(Certificate cer) throws KeyStoreException
	{
		X509Certificate xcer = (X509Certificate) cer, auxCer = null;
		String auxAlias = null;

		Enumeration<String> e = _mscapi.aliases();
		
		while (e.hasMoreElements())
		{
			auxAlias = (String) e.nextElement();
			auxCer = (X509Certificate) _mscapi.getCertificate(auxAlias);
			if ((auxCer.getIssuerDN().equals(xcer.getIssuerDN()))
					&& (auxCer.getSerialNumber().equals(xcer.getSerialNumber())))
			{
				return auxAlias;
			}
		}

		return null;
	}

	public void load(char[] pin) throws KeyStoreException, NoSuchAlgorithmException, IOException,
	CertificateException
	{
		/* Do nothing */
		// log.debug("loading .load(), doing nothing");
	}

	public Enumeration<String> aliases() throws KeyStoreException, Exception
	{
		return _mscapi.aliases();
	}

	public Certificate getCertificate(String alias) throws KeyStoreException, Exception
	{
		return _mscapi.getCertificate(alias);
	}

	public Certificate[] getUserCertificates() throws KeyStoreException, Exception
	{
		Vector<Certificate> certs = new Vector<Certificate>();
		Certificate tmp_cert;

		for (Enumeration<String> e = this.aliases(); e.hasMoreElements();)
		{
			tmp_cert = this.getCertificate((String) e.nextElement());
			certs.add(tmp_cert);
		}

		Certificate[] res = new Certificate[certs.size()];
		certs.toArray(res);

		return res;
	}

	public Key getKey(String alias) throws KeyStoreException, Exception
	{
		System.out.println("SunMSCapi Alias: " + alias);
		return _mscapi.getKey(alias, null);
	}

	public Provider getProvider()
	{
		return _mscapi.getProvider();
	}

	public void setProvider(Provider provider) throws Exception
	{
		//Does nothing, seems non sense by this time.
		throw new Exception("Method not implemented");
	}

	public byte[] signMessage(byte[] toSign, String alias) throws NoSuchAlgorithmException,
	Exception
	{
		byte[] b = null;
		return b;
	}

	public SupportedKeystore getName()
	{
		return SupportedKeystore.MSCAPI;
	}

	public String getTokenName()
	{
		return "Sun Windows Capi";
	}

	public void cleanUp()
	{
		_mscapi = null;
		Runtime.getRuntime().gc();
	}
}
