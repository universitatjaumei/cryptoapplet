package es.uji.security.keystore;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * <pre>
 *  Keystores interface, by the time we support:
 *    Mozilla native certificate store.
 *    Microsoft CryptoApi native store.
 *    Clauer store (work in progress).
 * </pre>
 * 
 * @author PSN
 */

public interface IKeyStoreHelper
{
	public static final String MOZILLA_KEY_STORE = "MozillaKeyStore";
	public static final String CLAUER_KEY_STORE  = "ClauerKeyStore";
	public static final String MSCAPI_KEY_STORE  = "MSCapiKeyStore";
	public static final String PKCS12_KEY_STORE  = "PKCS12KeyStore";
	public static final String PKCS11_KEY_STORE  = "PKCS11KeyStore";
	
	public void load(char[] pin) throws KeyStoreException, NoSuchAlgorithmException, IOException, CertificateException, Exception;
	
	public Enumeration aliases() throws KeyStoreException, Exception;

	public Certificate getCertificate(String alias) throws KeyStoreException, Exception;
	
	public Certificate[] getUserCertificates() throws KeyStoreException, Exception;

	public Key getKey(String alias) throws KeyStoreException, Exception;

	public String getAliasFromCertificate(Certificate cer)	throws Exception;
	
	public Provider getProvider();

	public String getName();
	
	public String getTokenName();
	
	public byte[] signMessage(byte[] toSign, String alias) throws NoSuchAlgorithmException, Exception;

	public void cleanUp();
}
