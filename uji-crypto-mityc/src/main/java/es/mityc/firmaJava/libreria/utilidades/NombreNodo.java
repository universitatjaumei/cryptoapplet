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
package es.mityc.firmaJava.libreria.utilidades;


/**
 * Clase para indicar nombres de elementos
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */
public class NombreNodo {
	private String namespace;
	private String localname;
	public NombreNodo(String namespace, String localname) {
		this.namespace = namespace;
		this.localname = localname;
	}
	@Override
	public boolean equals(Object obj) {
		if (obj instanceof NombreNodo) {
			NombreNodo nodo = (NombreNodo) obj;
			if (namespace == null) {
				if (nodo.namespace != null)
					return false;
			} else if (!namespace.equals(nodo.namespace))
				return false;
			if (localname.equals(nodo.localname))
				return true;
		}
		return false;
	}
	public String getNamespace() {
		return namespace;
	}
	public String getLocalname() {
		return localname;
	}
}
