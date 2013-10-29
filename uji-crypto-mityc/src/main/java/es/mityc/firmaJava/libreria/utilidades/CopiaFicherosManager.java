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
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.zip.Adler32;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.firmaJava.configuracion.Configuracion;
import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.excepciones.FilesNotAvalaibleException;
import es.mityc.firmaJava.libreria.utilidades.UtilidadSistemaOperativo.SO;

/**
 * Utilidad para el copiado de ficheros con integridad.
 * 
 * Esta librería accede a un fichero de propiedades donde se relaciona una clave con un conjunto de recursos. Bajo petición puede copiar
 * esos recursos a un lugar físico. En caso de ya existir comprueba la integridad de esos ficheros y si no la cumple procede a su sustitución.
 * 
 * Recupera la información del fichero de propiedades "rescopfil".
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class CopiaFicherosManager {
	
	private static final Log log = LogFactory.getLog(CopiaFicherosManager.class);
	
	private static CopiaFicherosManager instance;
	static {
		instance = new CopiaFicherosManager();
	}
	
	private static final int BUFFER_IN_SIZE = 32000;
	private static final int BUFFER_OUT_SIZE = 4096;
	
	private static final String STR_RESCOPFIL = "rescopfil";
	private static final String STR_FILE_DOT = "file.";
	private static final String STR_DOT_NAME = ".name";
	private static final String STR_DOT_RES = ".res";
	private static final String STR_DOT_ADLER32 = ".Adler32";
	private static final String STR_DOT_SIZE = ".size";
	
	private static final String[] STR_OS_NAME_WIN = {"windows.", "windows4.", "windows5."};
	private static final String[] STR_OS_NAME_LIN = {"linux.", "linux24.", "linux26."};
	
	
	private ResourceBundle props = null;
	
	/**
	 * Constructor
	 */
	public CopiaFicherosManager() {
		try {
			props = ResourceBundle.getBundle(STR_RESCOPFIL);
		} catch (MissingResourceException ex) {
			log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_ERROR_16), ex);
		}
	}
	
	
	/**
	 * Devuelve una instancia del manager
	 * @return
	 */
	public static CopiaFicherosManager getInstance() {
		return instance;
	}
	
	/**
	 * Comprueba si hay ficheros relacionados con el sistema operativo y si los hay, comprueba si es necesario volver a copiarlos
	 * (comprobando su integridad).
	 * 
	 * <br/><br/>
	 * Para buscar los ficheros relacionados con el sistema operativo compone un nombre dependiente del sistema operativo y le añade
	 * el addendum indicado. Sistemas operativos que busca:
	 * <ul>
	 *   <li>Windows</li>
	 *   <li>Linux</li>
	 * </ul>
	 * 
	 * @param dir Directorio donde se copiarán los ficheros
	 * @param addendum Cadena extra que se añadirá para buscar los ficheros (no se añade nada si es <code>null</code>). 
	 * @throws FilesNotAvalaibleException si no existe la clave indicada o algunos de los ficheros como recurso
	 * TODOLARGO: cambiar la comprobación de adler32 a sha-2 para endurecer las posibilidades de colisión (comprobar el impacto en rendimiento)
	 */
	public String copiaFicherosOS(String dir, String addendum) throws FilesNotAvalaibleException {
		String clave;
		SO so = UtilidadSistemaOperativo.getSO();
		if (so.isWindows()) {
			if ("4".equals(so.getVersion()))
				clave = STR_OS_NAME_WIN[1] + addendum;
			else if ("5".equals(so.getVersion()))
				clave = STR_OS_NAME_WIN[2] + addendum;
			else
				clave = STR_OS_NAME_WIN[0] + addendum;
		}
		else if (so.isLinux()) {
			if ("2.6".equals(so.getVersion()))
				clave = STR_OS_NAME_LIN[2] + addendum;
			else
				clave = STR_OS_NAME_LIN[0] + addendum;
		}
		else
			throw new FilesNotAvalaibleException("Sistema operativo no reconocido");
		// si no se ha indicado directorio busca uno entre los disponibles del path
		if (dir == null) {
			File fileDir = new File(System.getProperty(ConstantesXADES.USER_HOME) + File.separator + Configuracion.getNombreDirExterno());
			if (!fileDir.exists()) {
				if (!fileDir.mkdir())
					throw new FilesNotAvalaibleException("No se pudo crear directorio de aplicación");
			}
			updateLibraryPath(fileDir.getAbsolutePath());
    		dir = fileDir.getAbsolutePath();
		}
		else {
			updateLibraryPath(dir);
		}
		log.debug("Copiando ficheros de: " + clave + " en " + dir);
		copiaFicheros(dir, clave);
		return dir;
	}
	
	/**
	 * Actualiza la variable java.library.path con la nueva ruta indicada.
	 * 
	 * <br/><br/>Esta variable permite indicar dónde se encuentran las librerías JNI de usuario que se van a utilizar.
	 *  
	 * @param path Nueva ruta a incluir
	 */
	public void updateLibraryPath(String path) {
		String libPath = System.getProperty("java.library.path");
		File fileDir = new File(path) ;
		if (!libPath.contains(fileDir.getAbsolutePath())) {
			libPath = fileDir.getAbsolutePath() + File.pathSeparator + libPath;
			System.setProperty("java.library.path", libPath);
			try {
    			Field fieldSysPath = ClassLoader.class.getDeclaredField("sys_paths");
    			fieldSysPath.setAccessible(true);
    			if (fieldSysPath != null)
    				fieldSysPath.set(System.class.getClassLoader(), null);
			} catch (NoSuchFieldException ex) {
				log.error("Error estableciendo path", ex);
			} catch (IllegalAccessException ex) {
				log.error("Error estableciendo path", ex);
			}
		}
	}
	
	/**
	 * Comprueba si hay ficheros relacionados con la clave indicada y si los hay, comprueba si es necesario volver a copiarlos
	 * (comprobando su integridad).
	 * 
	 * @param dir Directorio donde se copiarán los ficheros
	 * @param clave Clave donde se agrupan los ficheros que se comprobarán/copiarán
	 * @throws FilesNotAvalaibleException si no existe la clave indicada o algunos de los ficheros como recurso
	 * TODOLARGO: cambiar la comprobación de adler32 a sha-2 para endurecer las posibilidades de colisión (comprobar el impacto en rendimiento)
	 */
	public void copiaFicheros(String dir, String clave) throws FilesNotAvalaibleException {
		if (props != null) {
			try {
				String conjunto = props.getString(clave);
				StringTokenizer st = new StringTokenizer(conjunto, ConstantesXADES.COMA);
				boolean hasMore = st.hasMoreTokens();
				while (hasMore) {
					// Recupera los datos relacionados con ese fichero. AppPerfect: falsos positivos, las expresiones no son constantes
					String fichero = st.nextToken();
					hasMore = st.hasMoreTokens();
					String nombreFichero = props.getString(STR_FILE_DOT + fichero + STR_DOT_NAME);
					String resname = props.getString(STR_FILE_DOT + fichero + STR_DOT_RES);
					long crcValue = Long.parseLong(props.getString(STR_FILE_DOT + fichero + STR_DOT_ADLER32));
					long size = Long.parseLong(props.getString(STR_FILE_DOT + fichero + STR_DOT_SIZE));
					copyLibrary(dir, nombreFichero, resname, crcValue, size);
				}
			} catch (MissingResourceException ex) {
				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_ERROR_17) + 
						ConstantesXADES.ESPACIO + clave);
				throw new FilesNotAvalaibleException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_ERROR_18));
			} catch (NumberFormatException ex) {
				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_ERROR_19) + 
						ConstantesXADES.ESPACIO + clave + ConstantesXADES.ESPACIO + 
						ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_ERROR_20), ex);
				throw new FilesNotAvalaibleException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_ERROR_18));
			}
		}
		else
			throw new FilesNotAvalaibleException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_ERROR_18));
	}
	
	/**
	 * Comprueba si existe el fichero indicado en la ruta y si no existe o no está íntegro procede a volverlo a copiar
	 * 
	 * @param dir
	 * @param clave
	 */
	private void copyLibrary(String dir, String fichero, String resname, long crcValue, long size) throws FilesNotAvalaibleException {
        InputStream entrada = null;
        OutputStream salida = null;
        try {
	    	File file = new File(dir, fichero);
	    	if ((!file.exists()) || (!checkIntegrityFile(file, crcValue, size))) {
	    		if (log.isTraceEnabled())
	    			log.trace(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_INFO_5) + file.getAbsolutePath());
	        	entrada = new BufferedInputStream(this.getClass().getClassLoader().getResourceAsStream(resname), BUFFER_IN_SIZE);
	        	salida = new BufferedOutputStream(new FileOutputStream(file));
	    		byte[] buffer = new byte[BUFFER_OUT_SIZE];
				int readed = entrada.read(buffer);
				while (readed > 0) {
					salida.write(buffer, 0, readed);
					readed = entrada.read(buffer);
				}
				salida.flush();
	    	}
        } catch (FileNotFoundException ex) {
        	log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_ERROR_21), ex);
        	throw new FilesNotAvalaibleException(ex);
        } catch (SecurityException ex) {
        	log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_ERROR_22), ex);
        	throw new FilesNotAvalaibleException(ex);
        } catch (IOException ex) {
        	log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_ERROR_23), ex);
        	throw new FilesNotAvalaibleException(ex);
		}
    	finally {
        	if (entrada != null) {
        		try {
        			entrada.close();
        		} catch (IOException e) {
        			log.error(e.getMessage());
        		}
        	}
        	if (salida != null)
        		try {
        			salida.close();
        		} catch (IOException e) {
        			log.error(e.getMessage());
        		}
        }
	}
	
	/**
	 * Comprueba si el fichero indicado es íntegro.
	 * 
	 * @param file
	 * @param crcValue
	 * @param size
	 * @return
	 */
	private boolean checkIntegrityFile(File file, long crcValue, long size) throws FileNotFoundException, IOException {
		if (log.isTraceEnabled())
			log.trace(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_INFO_6) + 
					ConstantesXADES.ESPACIO + file.getAbsolutePath());
		if (!file.exists())
			return false;
		// Primero comprueba el tamaño
		if (file.length() != size)
			return false;
		// después comprueba el crc
		Adler32 crc = new Adler32();
        InputStream entrada = new BufferedInputStream(new FileInputStream(file), BUFFER_IN_SIZE);
		byte[] buffer = new byte[BUFFER_OUT_SIZE];
		int readed = entrada.read(buffer);
		while (readed > 0) {
			crc.update(buffer, 0, readed);
			readed = entrada.read(buffer);
		}
		if (log.isTraceEnabled())
			log.trace(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_INFO_7) + 
					ConstantesXADES.ESPACIO + crc.getValue() + ConstantesXADES.ESPACIO + 
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAMOZILLA_INFO_8)+ 
					ConstantesXADES.ESPACIO + crcValue);
		if (crc.getValue() != crcValue)
			return false;
		return true;
	}	
}