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
package es.mityc.firmaJava.libreria.xades;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * Clase para manejar nodos del tipo DigestAlgAndValueType
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class DigestAlgAndValueType {
	
	private String method;
	private String value;
	
	/**
	 * Construye el objeto indicándole los datos que contendrá
	 */
	public DigestAlgAndValueType(String method, String value) {
		this.method = method;
		this.value = value.replace(" ", "").replace("\n", "").replace("\r", "");
	}

	/**
	 * Construye el objeto a partir de un nodo del tipo DigestAlgAndValueType
	 * @param padre
	 */
	public DigestAlgAndValueType(Element padre) throws InvalidInfoNodeException {
		NodeList nodos = padre.getChildNodes();
		if (nodos.getLength() != 2)
			throw new InvalidInfoNodeException("Longitud del nodo no esperada");

		if ((nodos.item(0).getNodeType() != Node.ELEMENT_NODE) ||
			(nodos.item(1).getNodeType() != Node.ELEMENT_NODE))
			throw new InvalidInfoNodeException("Formato de los nodos no esperado");
		Element digestMethod = (Element)nodos.item(0);
		Element digestValue =  (Element)nodos.item(1);
		
		if (!new NombreNodo(ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.LIBRERIAXADES_DIGEST_METHOD).equals(
			 new NombreNodo(digestMethod.getNamespaceURI(), digestMethod.getLocalName())))
			throw new InvalidInfoNodeException("Nodo hijo no es DigestMethod");
		if (!new NombreNodo(ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.LIBRERIAXADES_DIGESTVALUE).equals(
			 new NombreNodo(digestValue.getNamespaceURI(), digestValue.getLocalName())))
			throw new InvalidInfoNodeException("Nodo hijo no es DigestValue");
		
		if (!digestMethod.hasAttribute(ConstantesXADES.ALGORITHM))
			throw new InvalidInfoNodeException("Atributo requerido no presente" + ConstantesXADES.ALGORITHM);
		this.method = digestMethod.getAttribute(ConstantesXADES.ALGORITHM);
		
		this.value = digestValue.getFirstChild().getNodeValue();
		if (this.value == null)
			throw new InvalidInfoNodeException("Contenido de valor de digest vacío");
		this.value = this.value.replace(" ", "").replace("\n", "").replace("\r", "");
	}
	
	// TODOLARGO: hacer un algoritmo que devuelva  el OID del algoritmo. 
	
	public String getMethod() {
		return method;
	}

	public void setMethod(String method) {
		this.method = method;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value.replace(" ", "").replace("\n", "").replace("\r", "");
	}
	
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof DigestAlgAndValueType) {
			DigestAlgAndValueType huella = (DigestAlgAndValueType) obj;
			if (!method.equals(huella.method))
				return false;
			if (value.equals(huella.value))
				return true;
		}
		return false;
	}
	
	

}
