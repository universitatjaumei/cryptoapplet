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

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * Interfaz que ha de cumplir una implementación de un elemento del esquema xades
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public abstract class AbstractXADESElement extends AbstractXDsigElement {
	
	protected XAdESSchemas schema;
	protected String namespaceXAdES;
	
	protected AbstractXADESElement(XAdESSchemas schema) {
		super();
		this.schema = schema;
	}
	
	
	/**
	 * @return the schema
	 */
	public XAdESSchemas getSchema() {
		return schema;
	}


	/**
	 * @param schema the schema to set
	 */
	public void setSchema(XAdESSchemas schema) {
		this.schema = schema;
	}

	/**
	 * Este elemento lo pueden hacer público los elementos
	 * 
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXDsigElement#createElement(org.w3c.dom.Document, java.lang.String)
	 */
	protected Element createElement(Document doc, String namespaceXAdES) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		return createElement(doc);
	}
	
	/**
	 * Este elemento lo pueden hacer público los elementos
	 * 
	 * @param doc
	 * @param namespaceXDsig
	 * @param namespaceXAdES
	 * @return
	 * @throws InvalidInfoNodeException
	 */
	protected Element createElement(Document doc, String namespaceXDsig, String namespaceXAdES) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		return super.createElement(doc, namespaceXDsig);
	}
	
	/**
	 * Este metodo lo puede hacer público los tipos
	 * 
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXDsigElement#addContent(org.w3c.dom.Document, org.w3c.dom.Element, java.lang.String)
	 */
	protected void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		addContent(element);
	}

	/**
	 * Este metodo lo puede hacer público los tipos.
	 * @param doc
	 * @param element
	 * @param namespaceXAdES
	 * @param namespaceXDsig
	 * @throws InvalidInfoNodeException
	 */
	protected void addContent(Element element, String namespaceXAdES, String namespaceXDsig) throws InvalidInfoNodeException {
		setNamespaceXAdES(namespaceXAdES);
		super.addContent(element, namespaceXDsig);
	}

	/**
	 * @return the namespaceXAdES
	 */
	public String getNamespaceXAdES() {
		return namespaceXAdES;
	}


	/**
	 * @param namespaceXAdES the namespaceXAdES to set
	 */
	public void setNamespaceXAdES(String namespaceXAdES) {
		this.namespaceXAdES = namespaceXAdES;
	}


}
