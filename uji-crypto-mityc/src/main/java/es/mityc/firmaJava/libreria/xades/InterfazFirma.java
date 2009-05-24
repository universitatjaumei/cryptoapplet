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
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA o consulte
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2008 Ministerio de Industria, Turismo y Comercio
 * 
 */

package es.mityc.firmaJava.libreria.xades;

import java.security.cert.X509Certificate;
import java.util.Vector;

import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;

/**
 * Interfaz para obtener los certificados como vector de X509Certificate 
 * independientemente del navegador o repositorio de certificados
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public interface InterfazFirma {
    
	/**
     * Obtiene los certificados como Vector de X509Certificate
     * @param storageName Alamcen de certificado (IE) o configuración (Firefox)
     * @return los certificados como vector de X509Certificate
     */
    Vector<X509Certificate> getAllCertificates(String storageName) throws FirmaXMLError;
    
}