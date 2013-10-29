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

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Esquemas de firma XAdES
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0 beta
 */

public enum TipoSellosTiempo implements ConstantesXADES{

	CLASE_T(LITERAL_CLASE_T),
	CLASE_X_TIPO_1(LITERAL_CLASE_X_TIPO_1),
	CLASE_X_TIPO_2(LITERAL_CLASE_X_TIPO_2),
	CLASE_A(LITERAL_CLASE_A);

	private String name;

	private TipoSellosTiempo(String name) {
		this.name = name;
	}

	public String getTipoSello() {
		return name;
	}
}