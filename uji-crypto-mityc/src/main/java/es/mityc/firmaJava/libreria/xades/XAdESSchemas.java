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

/**
 * Esquemas de firma XAdES
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0 beta
 */

public enum XAdESSchemas implements Comparable<XAdESSchemas> {

	XAdES_111("1.1.1", "http://uri.etsi.org/01903/v1.1.1#"),
	XAdES_122("1.2.2", "http://uri.etsi.org/01903/v1.2.2#"),
	XAdES_132("1.3.2", "http://uri.etsi.org/01903/v1.3.2#");

	private String name;
	private String uri;

	private XAdESSchemas(String name, String uri) {
		this.name = name;
		this.uri = uri;
	}
	
	public String getSchemaVersion() {
		return name;
	}

	@Override
	public String toString() {
		return name;
	}

	public String getSchemaUri() {
		return uri;
	}
	
	public static XAdESSchemas getXAdESSchema(String esquemaUri) {
		XAdESSchemas resultado = null;
		if (esquemaUri != null) {
			if (XAdES_111.uri.equals(esquemaUri)) {
				resultado = XAdES_111;
			} else if (XAdES_122.uri.equals(esquemaUri)) {
				resultado = XAdES_122;
			} else if (XAdES_132.uri.equals(esquemaUri)) {
				resultado = XAdES_132;
			}
		}
		return resultado;
	}
}


