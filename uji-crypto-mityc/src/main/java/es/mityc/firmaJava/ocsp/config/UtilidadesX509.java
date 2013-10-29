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

package es.mityc.firmaJava.ocsp.config;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;

import es.mityc.firmaJava.ocsp.Base64Coder;

/** 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public final class UtilidadesX509 implements ConstantesProveedores {

    private static Log logger = LogFactory.getLog(UtilidadesX509.class);
	private static final String STRING_EMPTY = EMPTY_STRING;
	
    public static boolean isEmpty (String valor) {
   	 return (valor == null || valor.trim().equals(STRING_EMPTY));
    }
    
	public static X509Certificate getCertificate (Object certObj) throws CertificateException {
		X509Certificate cert = null;
		CertificateFactory cf = CertificateFactory.getInstance(X_509);
		ByteArrayInputStream certStream = null;
		
		if (certObj instanceof String) {
			certStream = new ByteArrayInputStream(Base64Coder.decode((String) certObj));
		} else if (certObj instanceof byte[]) {
			certStream = new ByteArrayInputStream((byte[]) certObj);
		} else if (certObj instanceof InputStream) {
			certStream = (ByteArrayInputStream)certObj;		
		} else {
			throw new CertificateException (CERTIFICATE_TYPE_EXCEPTION);
		}
		
		try {
			cert = (X509Certificate) cf.generateCertificate(certStream);
		} catch (CertificateException e) {
			logger.error(e.getMessage());
			throw new CertificateException (e.getMessage());
		}
		return cert;
	}

	public static DERObject convertToDERObject(byte[] data) throws IOException
	{
	    ByteArrayInputStream inStream = new ByteArrayInputStream(data);
	    ASN1InputStream derInputStream = new ASN1InputStream(inStream);
	    return derInputStream.readObject();
	}

	public static ASN1OctetString getIssuerKeyHash(X509Certificate cert) throws IOException {
		ASN1OctetString issuerKeyHash = null;
		Digest digest = new SHA1Digest();
		byte[] resBuf = new byte[digest.getDigestSize()];
		byte[] bytes = cert.getIssuerX500Principal().getEncoded();
		
		digest.update(bytes, 0, bytes.length);
		digest.doFinal(resBuf, 0);
		
		// Busca el hash de la issuer public key
		// Busca el hash de la public key info de la CA expendedora en el certificado
		DERObject derObject = convertToDERObject(cert.getExtensionValue(X509Extensions.AuthorityKeyIdentifier.getId()));
		if (derObject instanceof DEROctetString)
	    {
			DEROctetString derOctetString = (DEROctetString)derObject;
			derObject = convertToDERObject(derOctetString.getOctets());
	    }
		ASN1Sequence aIs = ASN1Sequence.getInstance(derObject);
		issuerKeyHash = ASN1OctetString.getInstance(aIs.getObjectAt(0));
		
		return issuerKeyHash;
	}

	public static ASN1OctetString getIssuerNameHash(X509Certificate cert) {
		Digest digest = new SHA1Digest();
		byte[] resBuf = new byte[digest.getDigestSize()];
		byte[] bytes = cert.getIssuerX500Principal().getEncoded();
		
		digest.update(bytes, 0, bytes.length);
		digest.doFinal(resBuf, 0);
		ASN1OctetString issuerNameHash = new DEROctetString(resBuf);
		return issuerNameHash;
	}

	public static ASN1OctetString getSubjectNameHash(X509Certificate cert) {
		Digest digest = new SHA1Digest();
		byte[] resBuf = new byte[digest.getDigestSize()];
		byte[] bytes = cert.getSubjectX500Principal().getEncoded();
		
		digest.update(bytes, 0, bytes.length);
		digest.doFinal(resBuf, 0);
		ASN1OctetString issuerNameHash = new DEROctetString(resBuf);
		return issuerNameHash;
	}

	public static ASN1OctetString getSubjectKeyHash(X509Certificate cert) throws IOException {
		PublicKey pk = cert.getPublicKey();
		byte[] pkCertBytes = pk.getEncoded();
		DERObject der = convertToDERObject(pkCertBytes);
		ASN1Sequence seq = ASN1Sequence.getInstance(der);
		SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(seq);
		
		Digest digest = new SHA1Digest();
		byte[] resBuf = new byte[digest.getDigestSize()];
		byte[] bytes = spki.getPublicKeyData().getBytes();
		
		digest.update(bytes, 0, bytes.length);
		digest.doFinal(resBuf, 0);
		ASN1OctetString issuerKeyHash = new DEROctetString(resBuf);

		return issuerKeyHash;
		
	}
}
