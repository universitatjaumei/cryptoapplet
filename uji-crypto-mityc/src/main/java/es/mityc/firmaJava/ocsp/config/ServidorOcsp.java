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

package es.mityc.firmaJava.ocsp.config;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Contiene informacion sobre un servidor OCSP. 
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class ServidorOcsp implements Cloneable, ConstantesProveedores{
	
	private URI url = null;
	private String descripcion = EMPTY_STRING; 
	
	/**
	 * Constructor de la clase
	 * @param url Url del OCSP Responder
	 * @param descripcion Breve descripcion del servidor
	 * @throws URISyntaxException Si la url no es valida.
	 */
	public ServidorOcsp(String url, String descripcion) throws URISyntaxException {
		this.url = new URI (url);
		this.descripcion = descripcion;
	}
	/**
	 * Obtiene la descripcion del servidor.
	 * @return
	 */
	public String getDescripcion() {
		return descripcion;
	}
	
	/**
	 * Obtiene la URL del OCSP Responder
	 */
	public URI getUrl() {
		return url;
	}
	protected Object clone() throws CloneNotSupportedException {
		return (ServidorOcsp) super.clone();
	}
}
