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

import es.mityc.firmaJava.ocsp.RespuestaOCSP.TIPOS_RESPONDER;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */
public class OCSPResponderData {
	
	private TIPOS_RESPONDER tipoResponder = null;
	private String identificador = null;
	
	public OCSPResponderData() {}
	
	/**
	 * Almacena datos sobre los tipos de OCSP que se pueden dar en CompleteRevocationRefs
	 * 
	 * @param tipoResponder .- Discrimina si la respuesta OCSP fue proporcionada por nombre o por clave
	 * @param identificador .- Almacena el valor leído del nodo
	 */
	public OCSPResponderData (TIPOS_RESPONDER tipoResponder,
			String identificador) {
		this.tipoResponder = tipoResponder;
		this.identificador = identificador;	
	}
	
	public TIPOS_RESPONDER getTipoResponder() {
		return tipoResponder;
	}
	public void setTipoResponder(TIPOS_RESPONDER tipoResponder) {
		this.tipoResponder = tipoResponder;
	}
	public String getIdentificador() {
		return identificador;
	}
	public void setIdentificador(String identificador) {
		this.identificador = identificador;
	}
}
