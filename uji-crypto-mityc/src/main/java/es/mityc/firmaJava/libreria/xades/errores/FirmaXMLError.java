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

package es.mityc.firmaJava.libreria.xades.errores;

/**
 * Excepciones en la firma o validacion del XML
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class FirmaXMLError extends Exception {
    
    
    /**
     * Crea una nueva instancia de FirmaXMLError sin el mensaje de detalle.
     */
    public FirmaXMLError() {
    }
    
    /**
     * Crea una nueva instancia de FirmaXMLError con el mensaje de detalle.
     * @param msg El mensaje de detalle.
     */
    public FirmaXMLError(String msg) {
        super(msg);
    }

    /**
     * Crea una nueva instancia de FirmaXMLError con la Excepción especificada.
     * @param e Exception
     */
     public FirmaXMLError(Exception e) {
        super(e);
    }

	/**
	 * @param message
	 * @param cause
	 */
	public FirmaXMLError(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param cause
	 */
	public FirmaXMLError(Throwable cause) {
		super(cause);
	}
     
}
