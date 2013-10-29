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

import java.math.BigInteger;

/**
 * Clase encargada de almacenar información referida a los certificados X509Certificate 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class DatosX509 {
	
	private String algMethod = null;
	private String digestValue = null;
	private BigInteger serial = null;
	private String issuer = null;
	
	public DatosX509 () {}
	
	/**
	 * @param algMethod Método de cálculo de digest 
	 * @param digestvalue Es el valor de digest del certificado utilizando el algoritmo referido
	 * @param serial Es el número de serie del certificado
	 * @param issuer Es el nombre del emisor del certificado
	 */
	public DatosX509 (String algMethod, String digestValue, BigInteger serial, String issuer) {		
		this.algMethod = algMethod;
		this.digestValue = digestValue;
		this.serial = serial;
		this.issuer = issuer;
	}

	/**
	 * @return algMethod
	 */
	public String getAlgMethod() {
		return algMethod;
	}

	/**
	 * @param algMethod
	 */
	public void setAlgMethod(String algMethod) {
		this.algMethod = algMethod;
	}

	/**
	 * @return digestValue
	 */
	public String getDigestValue() {
		return digestValue;
	}

	/**
	 * @param digestValue
	 */
	public void setDigestValue(String digestValue) {
		this.digestValue = digestValue;
	}

	/**
	 * @return issuer
	 */
	public String getIssuer() {
		return issuer;
	}

	/**
	 * @param issuer
	 */
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	/**
	 * @return serial
	 */
	public BigInteger getSerial() {
		return serial;
	}

	/**
	 * @param serial
	 */
	public void setSerial(BigInteger serial) {
		this.serial = serial;
	}
}
