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

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 * 
 * 	TODO: incluir el tratamiento de la información en base6binary
 */
public class EncapsulatedPKIDataType extends AbstractXADESElement {
	
	private String id;
	private EncodingEnum encoding;
	private String value;

	/**
	 * @param schema
	 */
	public EncapsulatedPKIDataType(XAdESSchemas schema) {
		super(schema);
	}
	
	public EncapsulatedPKIDataType(XAdESSchemas schema, String id) {
		super(schema);
		this.id = id; 
	}

	public EncapsulatedPKIDataType(XAdESSchemas schema, String id, EncodingEnum encoding) {
		this(schema, id);
		this.encoding = encoding;
	}
	

	/**
	 * @return the id
	 */
	public String getId() {
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * @return the encoding
	 */
	public EncodingEnum getEncoding() {
		if ((!schema.equals(XAdESSchemas.XAdES_111)) && (!schema.equals(XAdESSchemas.XAdES_122)))
			return encoding;
		return null;
	}

	/**
	 * @param encoding the encoding to set
	 */
	public void setEncoding(EncodingEnum encoding) {
		this.encoding = encoding;
	}
	
	/**
	 * @return the value
	 */
	public String getValue() {
		return value;
	}

	/**
	 * @param value the value to set
	 */
	public void setValue(String value) {
		this.value = value;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof EncapsulatedPKIDataType) {
			EncapsulatedPKIDataType epdt = (EncapsulatedPKIDataType)obj;
			if (value.equals(epdt.value))
				return true;
		}
		return false;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXADESElement#addContent(org.w3c.dom.Element, java.lang.String, java.lang.String)
	 */
	@Override
	public void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES);
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		// Recupera los atributos
		if (element.hasAttribute(ConstantesXADES.ID))
			this.id = element.getAttribute(ConstantesXADES.ID);
		if (element.hasAttribute(ConstantesXADES.ENCODING)) {
			if ((schema.equals(XAdESSchemas.XAdES_111)) || (schema.equals(XAdESSchemas.XAdES_122)))
				throw new InvalidInfoNodeException("Atributo inválido para nodo EncapsulatedPKIDataType en esquema XAdES: " + schema.getSchemaUri());
			this.encoding = EncodingEnum.getEncoding(element.getAttribute(ConstantesXADES.ENCODING));
			if (this.encoding == null)
				throw new InvalidInfoNodeException("Encoding de nodo EncapsulatedPKIDataType desconocido: " + element.getAttribute(ConstantesXADES.ENCODING));
		}
		
		// Recupera la información del nodo
		Node node = element.getFirstChild();
		if (node.getNodeType() != Node.TEXT_NODE)
			throw new InvalidInfoNodeException("Nodo EncapsulatedPKIDataType no contiene CDATA como primer valor");

		this.value = node.getNodeValue();
		if (this.value == null)
			throw new InvalidInfoNodeException("Contenido de valor de EncapsulatedPKIDataType vacío");
		// TODO: chequear que es un contenido del tipo base64binary (en el encoding adecuado si viene indicado).
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if (value == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo EncapsulatedPKIDataType");
		if (id != null)
			element.setAttributeNS(null, ConstantesXADES.ID, id);
		EncodingEnum encoding = getEncoding();
		if (encoding != null)
			element.setAttributeNS(null, ConstantesXADES.ENCODING, encoding.getEncodingUri().toString());
		
		element.setTextContent(value);
	}

}
