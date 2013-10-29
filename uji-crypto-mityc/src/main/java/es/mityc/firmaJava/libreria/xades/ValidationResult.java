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

import java.util.ArrayList;
import java.util.Iterator;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class ValidationResult implements ConstantesXADES{
	
	private boolean validado;
	private ArrayList log;
	
	/**
	 * Crea una nueva instancia de ValidationResult()
	 */
	public ValidationResult()
	{
		this.validado 	= false;
		this.log		= new ArrayList();
	}
	
	/**
	 * Obtener el valor de log
	 * @return
	 */
	public ArrayList getLog() {
		return log;
	}
	
	/**
	 * Establece el valor de log
	 * @param log
	 */
	public void setLog(ArrayList log) {
		this.log = log;
	}
	
	/**
	 * Obtener el valor de validado
	 * @return
	 */
	public boolean isValidate() {
		return validado;
	}
	
	/**
	 * Devuelve el valor de validado
	 * @param validado
	 */
	public void setValidate(boolean validado) {
		this.validado = validado;
	}
	
	/**
	 * Este metodo añade un nuevo log a la lista
	 */
	public void addLog(String log)
	{
		this.log.add(log);
	}
	
	/**
	 * Esta clase devuelve todos los logs insertados
	 * @return
	 */
	public String writeLog()
	{
		StringBuffer log = new StringBuffer();
		for(Iterator it = this.log.iterator(); it.hasNext(); )
		{
			String _log = (String) it.next();
			log.append(_log);
			log.append(NUEVA_LINEA);
 		}
		return log.toString();
	}

}
