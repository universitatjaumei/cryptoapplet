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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Clase con utilidades para el tratamiento de fechas
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class UtilidadFechas implements ConstantesXADES {
	
	private static final String FORMATO_FECHA_CON_MILIS = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";
	private static final String FORMATO_FECHA_SIN_MILIS = "yyyy-MM-dd'T'HH:mm:ssZ";

	
	/**
	 * Parsea el contenido de una cadena del tipo xsd:DateTime en una fecha
	 *  
	 * @param fecha Cadena con la fecha en formato xsd:DateTime
	 * @return Date con la fecha, <code>null</code> si la fecha no se puede convertir 
	 */
	public static  Date parseaFechaXML(final String fecha) {
		// Primero trata el final de la cadena
		String res = new String(fecha);
		
		// Busca la T
		int t = res.indexOf("T");
		if (t == -1)
			return null;
		// A partir de la t busca los dos proximos ":"
		t = res.indexOf(":", t);
		if (t == -1)
			return null;
		t = res.indexOf(":", t+1);
		if (t == -1)
			return null;
		String formato;
		// Si hay . es que llegan decimales
		if (res.indexOf(".", t) > -1) {
			formato = FORMATO_FECHA_CON_MILIS;
		} else {
			formato = FORMATO_FECHA_SIN_MILIS;
		}
		// Si no hay ":" posterior es que debe terminar en Z
		if ((res.indexOf(":", t+1) == -1) && (!res.endsWith(ConstantesXADES.Z_FECHA)))
			res = res.concat(ConstantesXADES.Z_FECHA);
			
		// Si termina en Z lo cambia a UTC y si no es que termina en formato +##:##, lo pasa a +####
		if (res.endsWith(ConstantesXADES.Z_FECHA)) {
			res = res.replace(ConstantesXADES.Z_FECHA, ConstantesXADES.MILIS_FECHA);
		}
		else {
			res = res.substring(0, res.length() - 3).concat(res.substring(res.length() - 2));
		}
		SimpleDateFormat sdf = new SimpleDateFormat(formato);
		try {
			Date resultado = sdf.parse(res);
			return resultado;
		} catch (ParseException ex) {
		}
		return null;
	}
	
	/**
	 * Formatea una fecha para que se ajuste al tipo xsd:DateTime
	 * 
	 * @param fecha Fecha a formatear
	 * @return Fecha con el formato xsd:DateTime
	 */
	public static String formatFechaXML(final Date fecha) {
		SimpleDateFormat sdf = new SimpleDateFormat(FORMATO_FECHA_SIN_MILIS);
		String resultado = sdf.format(fecha);
		// Añade a la cadena los dos puntos
		resultado = resultado.substring(0, resultado.length() - 2).concat(DOS_PUNTOS).concat(resultado.substring(resultado.length()-2));
		return resultado;
	}

}
