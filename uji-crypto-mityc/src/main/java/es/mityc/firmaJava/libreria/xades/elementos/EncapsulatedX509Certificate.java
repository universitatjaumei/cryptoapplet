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
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
 * 
 */
package es.mityc.firmaJava.libreria.xades.elementos;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.Base64Coder;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class EncapsulatedX509Certificate extends EncapsulatedPKIDataType {
	
	/**
	 * @param schema
	 */
	public EncapsulatedX509Certificate(XAdESSchemas schema) {
		super(schema);
	}

	/**
	 * @param schema
	 * @param id
	 */
	public EncapsulatedX509Certificate(XAdESSchemas schema, String id) {
		super(schema, id);
	}

	/**
	 * @param schema
	 * @param id
	 * @param encoding
	 */
	public EncapsulatedX509Certificate(XAdESSchemas schema, String id,
			EncodingEnum encoding) {
		super(schema, id, encoding);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.EncapsulatedPKIDataType#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, schema.getSchemaUri(), ConstantesXADES.ENCAPSULATED_X_509_CERTIFICATE);
		super.load(element);

		// Si no está en DER está mal
		EncodingEnum encoding = getEncoding();
		if ((encoding != null) && (!encoding.equals(EncodingEnum.DER_ENCODED)))
			throw new InvalidInfoNodeException("El contenido de EncapsulatedX509Certificate debe estar en la codificación " + EncodingEnum.DER_ENCODED.getEncodingUri().toString());
				
		// Comprueba que el valor recogido es un certificado X509
		X509Certificate cert;
		try {
			cert = getX509Certificate();
		} catch (CertificateException ex) {
			throw new InvalidInfoNodeException("El contenido de EncapsulatedX509Certificate no es un certificado X509 válido", ex);
		}
		if (cert == null) {
			throw new InvalidInfoNodeException("El contenido de EncapsulatedX509Certificate no es un certificado X509 válido");
		}
	}
	
	public X509Certificate getX509Certificate() throws CertificateException {
		String value = getValue();
		if (value != null) {
			byte[] data;
			try {
				 data = Base64Coder.decode(value);
			} catch (IllegalArgumentException ex) {
				throw new CertificateException("Contenido base64 de EncapsulatedX509Certificate inválido", ex);
			}
			ByteArrayInputStream bais = new ByteArrayInputStream(data);
			CertificateFactory cf = CertificateFactory.getInstance(ConstantesXADES.X_509);
			X509Certificate cert = (X509Certificate)cf.generateCertificate(bais);
			return cert;
		}
		else 
			return null;
	}
	
	public void setX509Certificate(X509Certificate certificate) throws CertificateException {
		setValue(new String(Base64Coder.encode(certificate.getEncoded())));
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), schema.getSchemaUri(), ConstantesXADES.ENCAPSULATED_X_509_CERTIFICATE);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXADESElement#createElement(org.w3c.dom.Document, java.lang.String)
	 */
	@Override
	public Element createElement(Document doc, String namespaceXAdES) throws InvalidInfoNodeException {
		return super.createElement(doc, namespaceXAdES);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		Element res = doc.createElementNS(schema.getSchemaUri(), namespaceXAdES + ":" + ConstantesXADES.ENCAPSULATED_X_509_CERTIFICATE);
		super.addContent(res, namespaceXAdES);
		return res;
	}

}
