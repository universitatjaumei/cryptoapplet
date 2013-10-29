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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public abstract class AbstractXMLElement {
	
	protected AbstractXMLElement() {
		
	}
	
	/**
	 * Incluye la información de este nodo al elemento indicado. Implementado por los tipos.
	 * 
	 * @param doc
	 * @return
	 * @throws InvalidInfoNodeException
	 */
	protected void addContent(Element element) throws InvalidInfoNodeException {
		throw new UnsupportedOperationException("invalid operation");
	}

	/**
	 * Devuelve el árbol de nodos que representa este elemento. Implementado por los elementos finales.
	 * 
	 * @param doc Documento donde se agregará el elemento
	 */
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		throw new UnsupportedOperationException("invalid operation");
	}
	
	/**
	 * Lee la información del nodo
	 * 
	 * @param element elemento del que cuelga la información
	 * @throws InvalidInfoNodeException lanzada cuando la estructura de nodos leída es inválida
	 */
	public abstract void load(Element element) throws InvalidInfoNodeException;
	
	/**
	 * Compara otro objeto similar a ver si contienen la misma información
	 * 
	 * @param obj Objeto que ha de ser de la misma clase
	 * @return <code>true</code> si contienen la misma información, <code>false</code> en cualquier otro caso
	 */
	public abstract boolean equals(Object obj);
	
	/**
	 * Comprueba que el elemento indicado tiene el namespaceURI y el nombre esperados
	 * 
	 * @param element Elemento que chequear
	 * @param namespaceURI NamespaceURI esperado
	 * @param name Nombre esperado
	 * @throws InvalidInfoNodeException Se lanza cuando no se cumple lo esperado
	 */
	protected void checkElementName(Element element, String namespaceURI, String name) throws InvalidInfoNodeException {
		if (!isElementName(element, namespaceURI, name))
			throw new InvalidInfoNodeException("Elemento esperado (".concat(namespaceURI).concat(":").concat(name).concat(" Elemento obtenido ") + element.getNamespaceURI() + ":".concat(element.getLocalName()));
	}
	
	/**
	 * Comprueba si el elemento indicado tiene el nombre esperado
	 * 
	 * @param element Elemento que chequear
	 * @param namespaceURI NamespaceURI esperado
	 * @param name Nombre esperado
	 * @return
	 */
	protected boolean isElementName(Element element, String namespaceURI, String name) {
		if ((element != null) &&
			(new NombreNodo(namespaceURI, name).equals(
			 new NombreNodo(element.getNamespaceURI(), element.getLocalName()))))
			return true;
		return false;
	}
	
	/**
	 * Indica si el nodo pasado es o no del tipo al que se le hace la consulta
	 * 
	 * @param node
	 * @return
	 */
	protected boolean isThisNode(Node node) {
		throw new UnsupportedOperationException("invalid operation");
	}
	
	/**
	 * Convierte el nodo indicado a un elemento
	 * @param node
	 * @return <code>null<code> si el nodo indicado no es un Element
	 */
	protected Element nodeToElement(Node node) {
		Element element = null;
		if (node != null) {
			if (node.getNodeType() == Node.ELEMENT_NODE)
				element = (Element)node;
		}
		return element; 
	}

}
