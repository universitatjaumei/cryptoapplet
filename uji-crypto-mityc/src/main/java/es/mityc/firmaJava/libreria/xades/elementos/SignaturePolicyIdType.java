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

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class SignaturePolicyIdType extends AbstractXADESElement {
	
	private SigPolicyId sigPolicyId;
	private Transforms transforms;
	private SigPolicyHash sigPolicyHash;

	/**
	 * @param schema
	 */
	public SignaturePolicyIdType(XAdESSchemas schema) {
		super(schema);
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
		if ((sigPolicyId == null) || (sigPolicyHash == null))
			throw new InvalidInfoNodeException("Información insuficiente para escribir nodo SignaturePolicyIdType");
		
		element.appendChild(sigPolicyId.createElement(element.getOwnerDocument(), namespaceXAdES));
		
		if (transforms != null) {
			element.appendChild(transforms.createElement(element.getOwnerDocument(), namespaceXDsig));
		}
		
		element.appendChild(sigPolicyHash.createElement(element.getOwnerDocument(), namespaceXDsig, namespaceXAdES));
	}
	

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof SignaturePolicyIdType) {
			SignaturePolicyIdType spit = (SignaturePolicyIdType) obj;
			if ((sigPolicyId == null) || (spit.sigPolicyId == null) ||
				(sigPolicyHash == null) || (spit.sigPolicyHash == null))
				return false;
			if (((transforms == null) && (spit.transforms != null)) ||
					(transforms != null) && (spit.transforms == null))
					return false;
			if ((transforms != null) && (spit.transforms != null) &&
				(!transforms.equals(spit.transforms)))
				return false;
			if (!sigPolicyId.equals(spit.sigPolicyId))
				return false;
			if (sigPolicyHash.equals(spit.sigPolicyHash))
				return true;
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		// Nodo SigPolicyId
		Node node = element.getFirstChild();
		SigPolicyId sigPolicyId = new SigPolicyId(schema);
		if (!sigPolicyId.isThisNode(node))
			throw new InvalidInfoNodeException("Nodo SignaturePolicyIdType no tiene hijo SigPolicyId");
		sigPolicyId.load((Element)node);
		
		// Comprueba si el siguiente nodo es de transformadas
		node = node.getNextSibling();
		Transforms transforms = new Transforms();
		if (transforms.isThisNode(node))
			transforms.load((Element)node);
		else
			transforms = null;
		
		// Nodo SigPolicyHash
		if (node == null)
			throw new InvalidInfoNodeException("Nodo SignaturePolicyIdType no tiene hijo SigPolicyId");
		if (transforms != null)
			node = node.getNextSibling();
		SigPolicyHash sigPolicyHash = new SigPolicyHash(schema);
		if (!sigPolicyHash.isThisNode(node))
			throw new InvalidInfoNodeException("Nodo SignaturePolicyIdType no tiene hijo SigPolicyHash");
		sigPolicyHash.load((Element)node);
		
		// TODO: lectura de nodo SigPolicyQualifiers
		
		this.sigPolicyId = sigPolicyId;
		this.transforms = transforms;
		this.sigPolicyHash = sigPolicyHash;
	}

	/**
	 * @return the sigPolicyId
	 */
	public SigPolicyId getSigPolicyId() {
		return sigPolicyId;
	}

	/**
	 * @param sigPolicyId the sigPolicyId to set
	 */
	public void setSigPolicyId(SigPolicyId sigPolicyId) {
		this.sigPolicyId = sigPolicyId;
	}

	/**
	 * @return the transforms
	 */
	public Transforms getTransforms() {
		return transforms;
	}

	/**
	 * @param transforms the transforms to set
	 */
	public void setTransforms(Transforms transforms) {
		this.transforms = transforms;
	}

	/**
	 * @return the sigPolicyHash
	 */
	public SigPolicyHash getSigPolicyHash() {
		return sigPolicyHash;
	}

	/**
	 * @param sigPolicyHash the sigPolicyHash to set
	 */
	public void setSigPolicyHash(SigPolicyHash sigPolicyHash) {
		this.sigPolicyHash = sigPolicyHash;
	}

}
