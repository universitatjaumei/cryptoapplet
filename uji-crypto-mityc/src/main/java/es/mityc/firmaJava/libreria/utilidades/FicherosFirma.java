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

import java.io.File;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public final class FicherosFirma {
	
	//private static FicherosFirma ficherosFirma	= null;
	private static File[] ficheros = null;

	private FicherosFirma()
	{
		// Se crea una sola instancia de esta clase
	}
	
//	public static FicherosFirma getInstance()
//	{
//		if(ficherosFirma == null)
//		{
//			ficherosFirma = new FicherosFirma();
//		}
//		return ficherosFirma;
//	}
	
	
	public static File[] getFicheros() {
		File[] f = ficheros;
		return f;
	}

	public static void setFicheros(File[] ficheros) {
		File[] f = ficheros;
		FicherosFirma.ficheros = f;
	}
}
