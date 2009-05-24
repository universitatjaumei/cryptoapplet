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

import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.elementos.SignaturePolicyIdentifier;
import es.mityc.firmaJava.libreria.xades.errores.PolicyException;

/**
 * Escribe la política implícita en el nodo de firma indicado, sustituyendo la política previa indicada (si la hay).
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class PolicyImplied implements IFirmaPolicy {
	
	
	public PolicyImplied() {
		
	}

	/**
	 * 
	 * @see es.mityc.firmaJava.policy.IFirmaPolicy#escribePolicy(org.w3c.dom.Element, java.lang.String, java.lang.String, es.mityc.firmaJava.libreria.xades.XAdESSchemas)
	 */
	public void escribePolicy(Element nodoFirma, String namespaceDS, String namespaceXAdES, XAdESSchemas schema) throws PolicyException {
		SignaturePolicyIdentifier spi = new SignaturePolicyIdentifier(schema, true);
		UtilidadPolitica.escribePolicy(nodoFirma, namespaceDS, namespaceXAdES, schema, spi);
	}

}
