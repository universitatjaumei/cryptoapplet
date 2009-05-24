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
package es.mityc.firmaJava.policy;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.elementos.SignaturePolicyIdentifier;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;
import es.mityc.firmaJava.libreria.xades.errores.PolicyException;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class UtilidadPolitica {
	
	public static void escribePolicy(Element nodoFirma, String namespaceDS, String namespaceXAdES, XAdESSchemas schema, SignaturePolicyIdentifier spi) throws PolicyException {
		// Buscar el nodo SignedSignatureProperties para añadirle la política 
		NodeList list = nodoFirma.getElementsByTagNameNS(schema.getSchemaUri(), ConstantesXADES.SIGNED_SIGNATURE_PROPERTIES);
		if ((list.getLength() != 1) || (list.item(0).getNodeType() != Node.ELEMENT_NODE)) {
			throw new PolicyException("No hay nodo SignedSignatureProperties claro al que aplicar la política");
		}
		// Crea el nodo de política
		Element policy;
		try {
			policy = spi.createElement(nodoFirma.getOwnerDocument(), namespaceDS, namespaceXAdES);
		} catch (InvalidInfoNodeException ex) {
			throw new PolicyException("Error en la creación de la política:" + ex.getMessage(), ex);
		}
		
		NombreNodo SIGNING_TIME = new NombreNodo(schema.getSchemaUri(), ConstantesXADES.SIGNING_TIME); 
		NombreNodo SIGNING_CERTIFICATE = new NombreNodo(schema.getSchemaUri(), ConstantesXADES.SIGNING_CERTIFICATE); 
		NombreNodo SIGNATURE_POLICY_IDENTIFIER = new NombreNodo(schema.getSchemaUri(), ConstantesXADES.SIGNATURE_POLICY_IDENTIFIER); 
		// busca la posición donde poner el nodo
		Element signedSignatureProperties = (Element)list.item(0);
		Node node = signedSignatureProperties.getFirstChild();
		while (node != null) {
			if (node.getNodeType() != Node.ELEMENT_NODE)
				throw new PolicyException("Error en el formato de SignedSignatureProperties");
			NombreNodo nombre = new NombreNodo(node.getNamespaceURI(), node.getLocalName());
			if ((!nombre.equals(SIGNING_TIME)) && (!nombre.equals(SIGNING_CERTIFICATE)))
				break;
			node = node.getNextSibling();
		}
		// Si existe un nodo policy, lo sustituyes 
		if ((node != null) && (SIGNATURE_POLICY_IDENTIFIER.equals(new NombreNodo(node.getNamespaceURI(), node.getLocalName())))) {
			signedSignatureProperties.replaceChild(policy, node);
		} else {
			signedSignatureProperties.insertBefore(policy, node);
		}
	}


}
