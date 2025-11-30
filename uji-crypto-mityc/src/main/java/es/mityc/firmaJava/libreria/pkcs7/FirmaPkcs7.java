/**
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirlo y/o modificarlo
 * bajo los términos de la GNU Lesser General Public License (LGPL)
 * tal y como ha sido publicada por la Free Software Foundation; o
 * bien la versión 2.1 de la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
 * GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o ADECUACIÓN A UN
 * PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public License (LGPL) para más
 * detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL)
 * junto con esta librería; si no es así, escriba a la Free Software Foundation Inc.
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA o consulte
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2008 Ministerio de Industria, Turismo y Comercio
 * 
 */

package es.mityc.firmaJava.libreria.pkcs7;

import java.awt.Frame;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public final class FirmaPkcs7 implements ConstantesXADES
{
	//private static FirmaPkcs7 firma	= null;

	private FirmaPkcs7()
	{
		// Creates the one and only instance of the class
	}
	
//	public static FirmaPkcs7 getInstance()
//	{
//		if(firma == null)
//		{
//			firma = new FirmaPkcs7();
//		}
//		return firma;
//	}
	
	public static byte[] firmar(Frame padre, X509Certificate cert, byte[] datos)
		throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException,
		InvalidAlgorithmParameterException, NoSuchProviderException, CertStoreException,
		CMSException, IOException, OperatorCreationException, CertificateEncodingException
	{		
		byte[] bytesFirma = null;
		
		// Valida la tarjeta criptográfica
    	
		ValidaTarjeta vt = new ValidaTarjeta(padre);
    	vt.setVisible(true);
        // Esperamos mientras se valida la tarjeta...
    	vt.setVisible(false);
    		
    	// Genera la firma PKCS#7

		PrivateKey privateKey = vt.getPrivateKey(cert);

		CMSTypedData msg = new CMSProcessableByteArray(datos);
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

		ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
		DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
		gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider).build(signer, cert));

        KeyStore ks = vt.getKeyStore();
        String alias = vt.getAlias(cert);

		Certificate[] certChain = ks.getCertificateChain(alias);

		gen.addCertificates(new JcaCertStore(Arrays.asList(certChain)));

		CMSSignedData s = gen.generate(msg, true);
		bytesFirma = s.getEncoded();
		return bytesFirma;
	}
	
	public static byte[] firmar(ValidaTarjeta vt, X509Certificate cert, byte[] datos)
	throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException,
	InvalidAlgorithmParameterException, NoSuchProviderException, CertStoreException,
	CMSException, IOException, OperatorCreationException, CertificateEncodingException
	{		
		byte[] bytesFirma = null;

		PrivateKey privateKey = vt.getPrivateKey(cert);

		CMSTypedData msg = new CMSProcessableByteArray(datos);
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

		ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);
		DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
		gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider).build(signer, cert));

	    KeyStore ks = vt.getKeyStore();
	    String alias = vt.getAlias(cert);

		Certificate[] certChain = ks.getCertificateChain(alias);

		gen.addCertificates(new JcaCertStore(Arrays.asList(certChain)));

		CMSSignedData s = gen.generate(msg, true);
		bytesFirma = s.getEncoded();
		return bytesFirma;
	}
}