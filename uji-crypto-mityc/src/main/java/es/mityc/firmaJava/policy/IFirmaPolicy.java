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
import es.mityc.firmaJava.libreria.xades.errores.PolicyException;

/**
 * Interfaz que han de implementar las clases que añadan policies que gestiona el manager de policies.
 * 
 * Además los escritores de policies deben tener un constructor por defecto sin parámetros.
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public interface IFirmaPolicy {
	
	/**
	 * Este método deberá encargarse escribir la policy.
	 * 
	 * @param nodoFirma nodo raíz (de firma) de la firma en la que se quiere escribir la política
	 * @param namespaceDS Namespace de xmlDSig
	 * @param namespaceXAdES namespace de XAdES
	 * @param schema esquema de XAdEs
	 * 
	 * @throws lanza una excepción si no puede escribir la policy.
	 */
	public void escribePolicy(Element nodoFirma, String namespaceDS, String namespaceXAdES, XAdESSchemas schema) throws PolicyException;


}
