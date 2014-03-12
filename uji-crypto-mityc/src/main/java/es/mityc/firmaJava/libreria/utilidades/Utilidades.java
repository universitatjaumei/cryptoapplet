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

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.net.URL;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.HexEncoder;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Diversas funciones de utilidades para el desarrollo
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class Utilidades implements ConstantesXADES{
	
	static Log logger = LogFactory.getLog(Utilidades.class);

	private static final String  STR_ABRIENDO_CONEXION = "Abriendo conexion con ";
	private static final String  STR_TRES_PUNTOS = "...";

	public static boolean isAfirmativo (String valor){

		if ((valor != null) &&
				(((valor.trim()).toUpperCase()).equals(YES_MAYUSCULA) || 
						((valor.trim()).toUpperCase()).equals(SI_MAYUSCULA))){
			return true;
		}
		//En cualquier otro caso serÃ¡ falso
		return false;
	}

	public static boolean tieneValor(String valor) {
		if (valor != null && !valor.trim().equals(CADENA_VACIA)){
			return true;
		}
		return false;
	}

	public static boolean isEmpty (String valor) {
		return (valor == null || valor.trim().equals(CADENA_VACIA));
	}

	/**
	 * Este metodo recupera via URLConnection el fichero ubicado en la
	 * URL pasada como parametro. Devuelve un objeto tipo FileInputStream
	 * @return
	 */
	public static InputStream getInputStreamFromURL(String _url)
	throws Exception
	{
		URL url  = new URL(_url);
		logger.debug( STR_ABRIENDO_CONEXION + _url + STR_TRES_PUNTOS); 
		url.openConnection();
		// Copia el recurso al fichero local, usa un fichero remoto
		// si no esta especificado el nombre del fichero local
		InputStream is = url.openStream();

		System.out.flush();

		return is;
	}

	public static void writeInputStream (File sourceFile, Writer wtargetFile) throws IOException {
		byte[] buffer = new byte[510];
		int numBytes=0;
		BufferedInputStream bSourceFile = null;
		BufferedWriter targetFile = (BufferedWriter) wtargetFile;
		try {
			bSourceFile = new BufferedInputStream(new FileInputStream(sourceFile));
			String aux = CADENA_VACIA;
			do {
				numBytes = bSourceFile.read(buffer);
				if(numBytes == -1) break;
				aux = new String(Base64Coder.encode(buffer, numBytes));
				targetFile.write(aux);
			} while (numBytes >= 0);
		} 
		finally  {
			if (null != bSourceFile)
				bSourceFile.close();
		}

	}

	public static void writeInputStream (File sourceFile, File attachedFile, Writer wtargetFile) throws IOException {
		byte[] buffer = new byte[510];
		int numBytes=0;

		BufferedInputStream bSourceFile = null;
		BufferedWriter targetFile = (BufferedWriter) wtargetFile;

		BufferedWriter ficheroAdjuntoDatos = new BufferedWriter(new FileWriter(attachedFile));
		attachedFile.deleteOnExit();


		try {
			bSourceFile = new BufferedInputStream(new FileInputStream(sourceFile));
			String aux = CADENA_VACIA;
			do {
				numBytes = bSourceFile.read(buffer);
				if(numBytes == -1) break;
				aux = new String(Base64Coder.encode(buffer, numBytes));
				targetFile.write(aux);
				ficheroAdjuntoDatos.write(aux);
				targetFile.flush();
				ficheroAdjuntoDatos.flush();

			} while (numBytes >= 0);

		} 
		finally  {
			if (null != ficheroAdjuntoDatos)
				ficheroAdjuntoDatos.close();

			if (null != bSourceFile)
				bSourceFile.close();
		}

	}
	
	/**
	 * Codifica un array de bytes a Hexadecimal
	 * @param byte[] Datos a codificar
	 * @return String Datos codificados en hexadecimal
	 */
	public static String binary2String(byte[] data) {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			HexEncoder enc = new HexEncoder();
			enc.encode(data, 0, data.length, baos);
			return baos.toString();
		} catch (IOException ex) {
		}
		return null;
	}
	
	/**
	 * Compara dos arrays de bytes para ver si tienen el mismo contenido.
	 * 
	 * @param data1 
	 * @param data2
	 * @return <code>true</code> si tienen el mismo contenido, <code>false</code> en cualquier otro caso
	 */
	public static boolean isEqual(byte[] data1, byte[] data2) {
		if ((data1 == null) && (data2 == null))
			return true;
		if ((data1 == null) || (data2 == null))
			return false;
		if (data1.length != data2.length)
			return false;
		for (int i = 0; i < data1.length; i++) {
			if (data1[i] != data2[i])
				return false;
		}
		return true;
	}
}
