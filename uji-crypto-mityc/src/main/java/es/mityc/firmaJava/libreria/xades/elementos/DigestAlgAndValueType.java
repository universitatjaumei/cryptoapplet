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
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * Clase para manejar nodos del tipo DigestAlgAndValueType
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public abstract class DigestAlgAndValueType extends AbstractXADESElement {
	
	private DigestMethod method;
	private DigestValue value;
	
	public DigestAlgAndValueType(XAdESSchemas schema) {
		super(schema);
	}
	
	
	/**
	 * Construye el objeto indicándole los datos que contendrá
	 */
	public DigestAlgAndValueType(XAdESSchemas schema, String method, String value) {
		super(schema);
		this.method = new DigestMethod(method);
		this.value = new DigestValue(value);
	}

	public DigestMethod getMethod() {
		return method;
	}

	public void setMethod(DigestMethod method) {
		this.method = method;
	}

	public DigestValue getValue() {
		return value;
	}

	public void setValue(DigestValue value) {
		this.value = value;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof DigestAlgAndValueType) {
			DigestAlgAndValueType huella = (DigestAlgAndValueType) obj;
			if (!method.equals(huella.getMethod()))
				return false;
			if (value.equals(huella.getValue()))
				return true;
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXDsigElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		NodeList nodos = element.getChildNodes();
		if (nodos.getLength() != 2)
			throw new InvalidInfoNodeException("Longitud del nodo no esperada");

		if ((nodos.item(0).getNodeType() != Node.ELEMENT_NODE) ||
			(nodos.item(1).getNodeType() != Node.ELEMENT_NODE))
			throw new InvalidInfoNodeException("Formato de los nodos no esperado");

		method = new DigestMethod(null);
		method.load((Element)nodos.item(0));

		value = new DigestValue(null);
		value.load((Element)nodos.item(1));
	}


	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXADESElement#addContent(org.w3c.dom.Element, java.lang.String, java.lang.String)
	 */
	@Override
	public void addContent(Element element, String namespaceXAdES, String namespaceXDsig) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES, namespaceXDsig);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if ((method == null) || (value == null))
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo DigestAlgAndValueType");
		element.appendChild(method.createElement(element.getOwnerDocument(), namespaceXDsig));
		element.appendChild(value.createElement(element.getOwnerDocument(), namespaceXDsig));
	}
	

}
