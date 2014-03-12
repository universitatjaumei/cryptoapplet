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

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * Elemento DigestMethod (rfc 3275 4.3.3.5).
 *  
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class DigestMethod extends AbstractXDsigElement {
	
	// TODO: tratarlo como URI y no como String
	private String algorithm;

	/**
	 * @param namespaceXDSig
	 */
	public DigestMethod(String algorithm) {
		super();
		this.algorithm = algorithm;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#createElement(org.w3c.dom.Document)
	 */
	@Override
	protected Element createElement(Document doc) throws InvalidInfoNodeException {
		if (algorithm == null)
			throw new InvalidInfoNodeException("Información insuficiente para escribir elemento DigestMethod");
		Element res = doc.createElementNS(ConstantesXADES.SCHEMA_DSIG, namespaceXDsig + ":" + ConstantesXADES.DIGEST_METHOD);
		res.setAttributeNS(null, ConstantesXADES.ALGORITHM, algorithm);
		return res;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXDsigElement#createElement(org.w3c.dom.Document, java.lang.String)
	 */
	@Override
	public Element createElement(Document doc, String namespaceXDsig) throws InvalidInfoNodeException {
		return super.createElement(doc, namespaceXDsig);
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXDsigElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof DigestMethod) {
			DigestMethod method = (DigestMethod) obj;
			if (algorithm.equals(method.algorithm))
				return true;
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXDsigElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		checkElementName(element, ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.LIBRERIAXADES_DIGEST_METHOD);
		if (!element.hasAttribute(ConstantesXADES.ALGORITHM))
			throw new InvalidInfoNodeException("Atributo requerido no presente" + ConstantesXADES.ALGORITHM);
		this.algorithm = element.getAttribute(ConstantesXADES.ALGORITHM);
	}

	/**
	 * @return the algorithm
	 */
	public String getAlgorithm() {
		return algorithm;
	}

	/**
	 * @param algorithm the algorithm to set
	 */
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#isThisNode(org.w3c.dom.Node)
	 */
	@Override
	public boolean isThisNode(Node node) {
		return isElementName(nodeToElement(node), ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.LIBRERIAXADES_DIGEST_METHOD);
	}

}
