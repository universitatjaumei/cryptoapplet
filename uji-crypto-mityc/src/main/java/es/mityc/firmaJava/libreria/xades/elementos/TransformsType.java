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

import java.util.ArrayList;
import java.util.Iterator;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class TransformsType extends AbstractXDsigElement {
	
	private ArrayList<Transform> list;

	public TransformsType() {
		super();
	}
	
	public TransformsType(ArrayList<Transform> list) {
		super();
		this.list = list;
	}
	
	public void addTransform(Transform transform) {
		if (list == null)
			list = new ArrayList<Transform>();
		list.add(transform);
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXDsigElement#addContent(org.w3c.dom.Element, java.lang.String)
	 */
	@Override
	public void addContent(Element element, String namespaceXDsig) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXDsig);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if ((list == null) || (list.size() < 1))
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo TransformsType");
		Iterator<Transform> it = list.iterator();
		while (it.hasNext()) {
			element.appendChild(it.next().createElement(element.getOwnerDocument(), namespaceXDsig));
		}
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof TransformType) {
			TransformsType tt = (TransformsType) obj;
			ArrayList<Transform> comp = tt.list;
			if (((list == null) || (list.isEmpty())) &&
				((comp == null) || (comp.isEmpty())))
				return true;
			if (((list != null) && (comp != null)) && 
				 (list.size() == comp.size())) {
				Iterator<Transform> itThis = list.iterator();
				Iterator<Transform> itComp = comp.iterator();
				while (itThis.hasNext()) {
					if (!itThis.next().equals(itComp.next()))
						return false;
				}
				return true;
			}
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		NodeList nodos = element.getChildNodes();
		if (nodos.getLength() == 0)
			throw new InvalidInfoNodeException("Un nodo Trasforms debe tener al menos un hijo Transform");
		
		ArrayList<Transform> temp = new ArrayList<Transform>(nodos.getLength());
		for (int i = 0; i < nodos.getLength(); i++) {
			Node nodo = nodos.item(i);
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				throw new InvalidInfoNodeException("Hijo de Transforms no es un elemento");
			
			Transform transform = new Transform();
			transform.load((Element)nodo);
			temp.add(transform);
		}
		list = temp;
	}

	/**
	 * @return the list
	 */
	public ArrayList<Transform> getList() {
		return list;
	}

	/**
	 * @param list the list to set
	 */
	public void setList(ArrayList<Transform> list) {
		this.list = list;
	}

}
