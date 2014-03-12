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
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class SignaturePolicyIdentifierType extends AbstractXADESElement {
	
	private SignaturePolicyImplied signaturePolicyImplied;
	private SignaturePolicyId signaturePolicyId;

	/**
	 * @param schema
	 */
	public SignaturePolicyIdentifierType(XAdESSchemas schema) {
		super(schema);
	}
	
	public SignaturePolicyIdentifierType(XAdESSchemas schema, boolean isImplied) {
		super(schema);
		if (isImplied)
			signaturePolicyImplied = new SignaturePolicyImplied(schema);
		else
			signaturePolicyId = new SignaturePolicyId(schema);
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
		if (isImplied()) {
			element.appendChild(signaturePolicyImplied.createElement(element.getOwnerDocument(), namespaceXAdES));
		} else {
			if (signaturePolicyId == null)
				throw new InvalidInfoNodeException("Información insuficiente para escribir nodo SignaturePolicyId");
			element.appendChild(signaturePolicyId.createElement(element.getOwnerDocument(), namespaceXDsig, namespaceXAdES));
		}
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof SignaturePolicyIdentifierType) {
			SignaturePolicyIdentifierType spit = (SignaturePolicyIdentifierType) obj;
			if (isImplied()) {
				if (spit.isImplied())
					return true;
			}
			else {
				if ((signaturePolicyId == null) || (spit.isImplied()))
					return false;
				else if (signaturePolicyId.equals(spit.signaturePolicyId))
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
		NodeList nodes = element.getChildNodes();
		if (nodes.getLength() != 1)
			throw new InvalidInfoNodeException("Nodo SignaturePolicyIdentifierType debe tener un único hijo");

		// Nodo SignaturePolicyImplied o SignaturePolicyId
		Node node = nodes.item(0);
		SignaturePolicyImplied spi = new SignaturePolicyImplied(schema);
		if (spi.isThisNode(node)) {
			spi.load((Element)node);
			signaturePolicyImplied = spi;
		} else {
			SignaturePolicyId spid = new SignaturePolicyId(schema);
			spid.load((Element)node);
			signaturePolicyId = spid;
		}
	}

	/**
	 * @return the signaturePolicyImplied
	 */
	public SignaturePolicyImplied getSignaturePolicyImplied() {
		return signaturePolicyImplied;
	}

	/**
	 * @param signaturePolicyImplied the signaturePolicyImplied to set
	 */
	public void setSignaturePolicyImplied() {
		this.signaturePolicyImplied = new SignaturePolicyImplied(schema);
		this.signaturePolicyId = null;
	}

	/**
	 * @return the signaturePolicyId
	 */
	public SignaturePolicyId getSignaturePolicyId() {
		return signaturePolicyId;
	}

	/**
	 * @param signaturePolicyId the signaturePolicyId to set
	 */
	public void setSignaturePolicyId(SignaturePolicyId signaturePolicyId) {
		this.signaturePolicyId = signaturePolicyId;
		this.signaturePolicyId = null;
	}

	public boolean isImplied() {
		if (signaturePolicyImplied != null)
			return true;
		return false;
	}
}
