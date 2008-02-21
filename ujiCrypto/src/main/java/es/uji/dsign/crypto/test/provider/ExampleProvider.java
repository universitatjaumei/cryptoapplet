package es.uji.dsign.crypto.test.provider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * Example provider that demonstrates some of the new API features.
 *  . implement multiple different algorithms in a single class. Previously each
 * algorithm needed to be implemented in a separate class (e.g. one for MD5, one
 * for SHA-1, etc.)
 *  . multiple concurrent instances of the provider frontend class each
 * associated with a different backend.
 *  . it uses "unextractable" keys and lets the framework know which key objects
 * it can and cannot support
 * 
 * Note that this is only a simple example provider designed to demonstrate
 * several of the new features. It is not explicitly designed for efficiency.
 */
public final class ExampleProvider extends Provider
{
	private static final long serialVersionUID = 1L;

	public ExampleProvider()
	{
		super("UJI", 1.0, "JCA/JCE provider for " + "UJI");

		AccessController.doPrivileged(new PrivilegedAction<Object>() {
			public Object run()
			{
				put("Signature.SHA1withRSA", "es.uji.crypto.SHA1withRSA");
				put("Signature.SHA1withRSA ImplementedIn", "Software");
				put("Alg.Alias.Signature.sha-1WithRSAEncryption", "SHA1withRSA");
				put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", "SHA1withRSA");
				put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");
				put("MessageDigest.SHA", "es.uji.crypto.SHA1Digest");
				return null;
			}
		});
	}
}
