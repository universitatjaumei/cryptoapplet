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
 * Copyright 2007 Ministerio de Industria, Turismo y Comercio
 * 
 */

package es.mityc.firmaJava.ejemplos.xades;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.ValidarFirmaXML;

/**
 * Clase de ejemplo para realizar la validación de una firma XAdES
 * utilizando la librería XADES
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class EjemploXADESValidacion{
	
	private final static String FICHERO_XADES_VALIDO = "out.xml";
	private final static String FICHERO_XADES_NO_VALIDO = "out-mal.xml";

	public static void main(String[] args) {
		EjemploXADESValidacion p = new EjemploXADESValidacion();
		System.out.println("\n\nValidando una firma valida:");
		p.validarFichero(System.getProperty("user.dir") + "/" + FICHERO_XADES_VALIDO);
		System.out.println("-------------------------------------------------------");
		System.out.println("\n\nValidando una firma invalida:");
		p.validarFichero(System.getProperty("user.dir") + "/" + FICHERO_XADES_NO_VALIDO);
		System.out.println("-------------------------------------------------------");		
	}

	/**
	 * Método que realiza la validación de firma digital XAdES a un fichero y muestra el resultado
	 * @param fichero
	 */
	public void validarFichero(String fichero){

		// Se declara la estructura de datos que almacenará el resultado de la validación
		ResultadoValidacion result = null;
		
		// Se captura el fichero a validar
		File file = new File(fichero);

		// Se parsea el fichero a validar
		byte[] datos= null ;	
		FileInputStream fis = null;
		try 
		{
			fis = new FileInputStream(file) ;
			datos= new byte[fis.available()] ;
			fis.read(datos) ;
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			try {
				fis.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
		// Se instancia el validador y se realiza la validación
		try {
			ValidarFirmaXML vXml = new ValidarFirmaXML();
			result = vXml.validar(datos, null) ;
		} catch(Exception e){
			e.printStackTrace();
		}
		
		// Se muestra por consola el resultado de la validación
		boolean isValid = result.isValidate();
		System.out.println("-----------------");
		System.out.println("--- RESULTADO ---");
		System.out.println("-----------------");
		if(isValid){
			// El método getNivelValido devuelve el último nivel XAdES válido
			System.out.println("La firma es valida.\n" + result.getNivelValido());
		} else {
			// El método getLog devuelve el mensaje de error que invalidó la firma
			System.out.println("La firma NO es valida\n" + result.getLog());
		}
	}
}