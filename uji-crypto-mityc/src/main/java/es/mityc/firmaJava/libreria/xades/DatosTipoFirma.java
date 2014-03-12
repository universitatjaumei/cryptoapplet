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

import es.mityc.firmaJava.configuracion.EnumFormatoFirma;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */
public class DatosTipoFirma {
	
	private EnumFormatoFirma tipoXAdES = null;
	private boolean esXAdES_EPES = false;
	private boolean esXAdES_A = false;
	
	public DatosTipoFirma () {}
	
	/**
	 * Almacena información referente al tipo de firma XAdES obtenido
	 * 
	 * @param tipoFirma .- Indica el nivel de firma (XAdES-BES, XAdES-T, etc...)
	 * @param esXAdES_EPES .- Modificador que indica que la firma incluye políticas
	 * @param esXAdES_A .- Modificador que indica que la firma incluye un sello de tiempo del tipo A
	 */
	public DatosTipoFirma (EnumFormatoFirma tipoXAdES,
			boolean esXAdES_EPES,
			boolean esXAdES_A) {
		
		this.tipoXAdES = tipoXAdES;
		this.esXAdES_EPES = esXAdES_EPES;
		this.esXAdES_A = esXAdES_A;
	}

	public EnumFormatoFirma getTipoXAdES() {
		return tipoXAdES;
	}
	public void setTipoXAdES(EnumFormatoFirma tipoXAdES) {
		this.tipoXAdES = tipoXAdES;
	}
	public boolean esXAdES_EPES() {
		return esXAdES_EPES;
	}
	public void setEsXAdES_EPES(boolean esXAdES_EPES) {
		this.esXAdES_EPES = esXAdES_EPES;
	}
	public boolean esXAdES_A() {
		return esXAdES_A;
	}
	public void setEsXAdES_A(boolean esXAdES_A) {
		this.esXAdES_A = esXAdES_A;
	}
}
