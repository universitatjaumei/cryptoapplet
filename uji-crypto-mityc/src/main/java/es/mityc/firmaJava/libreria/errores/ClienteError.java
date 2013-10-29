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

package es.mityc.firmaJava.libreria.errores;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Excepción general del lado del cliente
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class ClienteError extends Exception implements ConstantesXADES{
    
	String mensaje = CADENA_VACIA;
     
	/**
     * Crea una nueva instancia de ClienteError sin el mensaje de detalle
     */
    public ClienteError() {
    }
    
    /**
     * Crea una nueva instancia de ClienteError con el mensaje de detalle
     * @param msg Detalle del mensaje
     */
    public ClienteError(String msg)
    {
        super(msg);
        this.mensaje = msg;
    }

    /**
     * Crea una nueva instancia de ClienteError
     * @param msg Excepción a propagar
     */
    public ClienteError(Throwable msg)
    {
        super(msg);
        this.mensaje = msg.getMessage() ;
    }
    
    /**
     * Este método obtiene el mensaje
     * @return mensaje Obtiene el mensaje
     */ 
    public String getMessage()
    {
        return mensaje ;
    }
}
