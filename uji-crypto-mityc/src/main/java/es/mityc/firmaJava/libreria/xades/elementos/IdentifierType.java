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

import java.net.URI;
import java.net.URISyntaxException;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public abstract class IdentifierType extends AbstractXADESElement {
	
	private URI uri;
	private QualifierEnum qualifier = null;

	/**
	 * @param namespaceXAdES
	 * @param namespaceXDSig
	 * @param schema
	 */
	public IdentifierType(XAdESSchemas schema) {
		super(schema);
	}
	
	public IdentifierType(XAdESSchemas schema, URI uri, QualifierEnum qualifier) {
		super(schema);
		this.uri = uri;
		this.qualifier = qualifier;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXDsigElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof IdentifierType) {
			IdentifierType it = (IdentifierType) obj;
			if (uri.equals(it.uri))
				return true;
		}
		return false;
	}

	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXDsigElement#load(org.w3c.dom.Element)
	 */
	@Override
	public void load(Element element) throws InvalidInfoNodeException {
		Node node = element.getFirstChild();
		if (node.getNodeType() != Node.TEXT_NODE) {
			throw new InvalidInfoNodeException("Nodo IdentifierType no contiene CDATA como primer valor");
		}
		
		// Obtiene el qualifier si existe
		qualifier = QualifierEnum.getQualifierEnum(element.getAttribute(ConstantesXADES.QUALIFIER));

		String data = node.getNodeValue();
		if (data == null)
			throw new InvalidInfoNodeException("No hay URI en nodo IdentifierType");
		try {
			// FIX: Cambia los espacios por %20 para evitar problemas con la clase URI
			data = data.replace(" ", "%20");
			uri = new URI(data);
		} catch (URISyntaxException ex) {
			throw new InvalidInfoNodeException("URI malformada en nodo IdentifierType", ex);
		}
	}

	protected void addContent(Element element) throws InvalidInfoNodeException {
		if (uri == null)
			throw new InvalidInfoNodeException("No hay información de URI para nodo IdentifierType");
		element.setTextContent(uri.toString());
		
		if (qualifier != null)
			element.setAttributeNS(null, ConstantesXADES.QUALIFIER, qualifier.toString());
	}

	/**
	 * @return the uri
	 */
	public URI getUri() {
		return uri;
	}

	/**
	 * @param uri the uri to set
	 */
	public void setUri(URI uri) {
		this.uri = uri;
	}

	/**
	 * @return the qualifier
	 */
	public QualifierEnum getQualifier() {
		return qualifier;
	}

	/**
	 * @param qualifier the qualifier to set
	 */
	public void setQualifier(QualifierEnum qualifier) {
		this.qualifier = qualifier;
	}
	
}
