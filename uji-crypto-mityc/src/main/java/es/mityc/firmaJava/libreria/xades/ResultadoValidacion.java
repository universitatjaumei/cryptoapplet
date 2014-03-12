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

import org.w3c.dom.Document;

import es.mityc.firmaJava.configuracion.EnumFormatoFirma;
import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class ResultadoValidacion implements ConstantesXADES{
	
	private boolean validado;
	private ResultadoEnum resultado;
	private String log;
	private String nivelValido;
	private EnumFormatoFirma EnumNivel; // Último nivel validado
	private Document doc;
	private DatosFirma datosFirma;

	/**
	 * Crea una nueva instancia de ValidationResult()
	 */
	public ResultadoValidacion()
	{
		this.validado 		= false;
		this.resultado		= ResultadoEnum.UNKNOWN;
		this.log			= CADENA_VACIA;
		this.nivelValido	= CADENA_VACIA;
	}
	
	/**
	 * 
	 * @return
	 */
	public String getLog() {
		return log;
	}
	
	/**
	 * 
	 * @param log
	 */
	public void setLog(String log) {
		this.log = log;
	}
	
	/**
	 * 
	 * @return
	 */
	public boolean isValidate() {
		return validado;
	}
	
	/**
	 * 
	 * @param validado
	 */
	public void setValidate(boolean validado) {
		this.validado = validado;
	}
	
	
	public ResultadoEnum getResultado() {
		return resultado;
	}

	public void setResultado(ResultadoEnum resultado) {
		this.resultado = resultado;
	}

	public Document getDoc() {
		return doc;
	}

	
	public void setDoc(Document doc) {
		this.doc = doc;
	}
	
	/**
	 * 
	 * @return
	 */
	public String getNivelValido() {
		return nivelValido;
	}
	
	/**
	 * 
	 * @param log
	 */
	public void setNivelValido(String nivelValido) {
		this.nivelValido = nivelValido;
	}

	/**
	 * 
	 * @return
	 */
	public DatosFirma getDatosFirma() {
		return datosFirma;
	}

	/**
	 * 
	 * @param datosFirma
	 */
	public void setDatosFirma(DatosFirma datosFirma) {
		this.datosFirma = datosFirma;
	}

	/**
	 * Último nivel validado
	 * @return EnumNivel
	 */
	public EnumFormatoFirma getEnumNivel() {
		return EnumNivel;
	}

	/**
	 *  Último nivel validado
	 * @param enumNivel
	 */
	public void setEnumNivel(EnumFormatoFirma enumNivel) {
		EnumNivel = enumNivel;
	}	
}
