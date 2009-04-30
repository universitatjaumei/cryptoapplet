package es.uji.security.keystore.mscapi;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * Security services provider that implments Digest and RSA Signature operation
 * SHA1withRSA from Microsft CryptoApi
 * 
 * @author PSN
 * 
 */

public final class MSCAPIProvider extends Provider
{
	private static final long serialVersionUID = 1L;

	public MSCAPIProvider()
	{
		super("UJI-MSCAPI", 1.0, "JCA/JCE provider for UJI");

		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			public Object run()
			{
				put("Signature.SHA1withRSA", "es.uji.dsign.crypto.SHA1withRSA");

				put("Signature.SHA1withRSA ImplementedIn", "Software");
				put("Alg.Alias.Signature.sha-1WithRSAEncryption", "SHA1withRSA");
				put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", "SHA1withRSA");
				put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");

				put("MessageDigest.SHA", "es.uji.dsign.crypto.SHA1Digest");

				// Format "Alias", "Actual Name"
				put("Alg.Alias.MessageDigest.SHA1", "SHA");
				put("Alg.Alias.MessageDigest.SHA-1", "SHA");
				put("Alg.Alias.MessageDigest.SHA-160", "SHA");

				return null;
			}
		});
	}
}
