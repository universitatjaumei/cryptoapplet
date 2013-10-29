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

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class CertificateValuesType extends AbstractXADESElement {
	
	private ArrayList<EncapsulatedX509Certificate> certificates;
	private String id;

	/**
	 * @param schema
	 */
	public CertificateValuesType(XAdESSchemas schema) {
		super(schema);
	}
	
	public CertificateValuesType(XAdESSchemas schema, ArrayList<EncapsulatedX509Certificate> certificates) {
		super(schema);
		this.certificates = certificates;
	}
	
	public void addEncapsulatedX509Certificate(EncapsulatedX509Certificate certificate) {
		if (certificates == null)
			certificates = new ArrayList<EncapsulatedX509Certificate>();
		certificates.add(certificate);
	}

	/**
	 * @return the certificates
	 */
	public ArrayList<EncapsulatedX509Certificate> getCertificates() {
		return certificates;
	}

	/**
	 * @param certificates the certificates to set
	 */
	public void setCertificates(ArrayList<EncapsulatedX509Certificate> certificates) {
		this.certificates = certificates;
	}

	/**
	 * @return the id
	 */
	public String getId() {
		return id;
	}

	/**
	 * @param id the id to set
	 */
	public void setId(String id) {
		this.id = id;
	}
	
	/**
	 * Busca en el listado de certificados si hay alguno certificado con esa id y lo devuelve.
	 * 
	 * @param id identificador a buscar
	 * @return devuelve el nodo certificado con esa id si lo encuentra, <code>null</code> en otro caso
	 */
	public EncapsulatedX509Certificate getEncapsulatedX509CertificateById(String id) {
		if ((certificates != null) && (id != null)) {
			Iterator<EncapsulatedX509Certificate> it = certificates.iterator();
			while (it.hasNext()) {
				EncapsulatedX509Certificate cert = it.next();
				String idCert = cert.getId();
				if (id.equals(idCert))
					return cert;
			}
		}
		return null;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof CertificateValuesType) {
			CertificateValuesType cvt = (CertificateValuesType) obj;
			ArrayList<EncapsulatedX509Certificate> comp = cvt.certificates;
			if (((certificates == null) || (certificates.isEmpty())) &&
				((comp == null) || (comp.isEmpty())))
				return true;
			if (((certificates != null) && (comp != null)) && 
				 (certificates.size() == comp.size())) {
				Iterator<EncapsulatedX509Certificate> itThis = certificates.iterator();
				Iterator<EncapsulatedX509Certificate> itComp = comp.iterator();
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
		// Recupera los atributos
		if (element.hasAttribute(ConstantesXADES.ID))
			this.id = element.getAttribute(ConstantesXADES.ID);

		NodeList nodos = element.getChildNodes();
		ArrayList<EncapsulatedX509Certificate> temp = new ArrayList<EncapsulatedX509Certificate>(nodos.getLength());
		for (int i = 0; i < nodos.getLength(); i++) {
			Node nodo = nodos.item(i);
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				throw new InvalidInfoNodeException("Hijo de CertificateValuesType no es un elemento");
			
			EncapsulatedX509Certificate certificate = new EncapsulatedX509Certificate(schema);
			certificate.load((Element)nodo);
			temp.add(certificate);
		}
		certificates = temp;
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXMLElement#addContent(org.w3c.dom.Element)
	 */
	@Override
	protected void addContent(Element element) throws InvalidInfoNodeException {
		if (certificates != null) {
			Iterator<EncapsulatedX509Certificate> it = certificates.iterator();
			while (it.hasNext()) {
				element.appendChild(it.next().createElement(element.getOwnerDocument(), namespaceXAdES));
			}
		}
		if (id != null)
			element.setAttributeNS(null, ConstantesXADES.ID, id);
	}
	
	/**
	 * @see es.mityc.firmaJava.libreria.xades.elementos.AbstractXADESElement#addContent(org.w3c.dom.Element, java.lang.String)
	 */
	@Override
	public void addContent(Element element, String namespaceXAdES) throws InvalidInfoNodeException {
		super.addContent(element, namespaceXAdES);
	}

}
