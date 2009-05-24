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

import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;


/**
 * Interfaz que ha de cumplir una implementación de un elemento del esquema XDsig
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public abstract class AbstractXDsigElement extends AbstractXMLElement {
	
	protected String namespaceXDsig;
	
	protected AbstractXDsigElement() {
		super();
	}
	
	/**
	 * Este método pueden hacerlo público los elementos finales.
	 * 
	 * @param doc
	 * @param namespace
	 * @return
	 * @throws InvalidInfoNodeException
	 */
	protected Element createElement(Document doc, String namespaceXDsig) throws InvalidInfoNodeException {
		setNamespaceXDsig(namespaceXDsig);
		return createElement(doc);
	}
	
	/**
	 * Este método pueden hacerlo público los tipos.
	 * 
	 * @param doc
	 * @param element
	 * @param namespace
	 * @throws InvalidInfoNodeException
	 */
	protected void addContent(Element element, String namespaceXDsig) throws InvalidInfoNodeException {
		setNamespaceXDsig(namespaceXDsig);
		addContent(element);
	}

	/**
	 * @return the namespaceXDsig
	 */
	public String getNamespaceXDsig() {
		return namespaceXDsig;
	}

	/**
	 * @param namespaceXDsig the namespaceXDsig to set
	 */
	public void setNamespaceXDsig(String namespaceXDsig) {
		this.namespaceXDsig = namespaceXDsig;
	}
	
}
