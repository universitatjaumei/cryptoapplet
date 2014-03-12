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


import java.security.KeyStore;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Clase de utilidades para los sistemas operativos / navegadores
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */
public class UtilidadSistemaOperativo { // implements ConstantesXADES
	
    private static Log log = LogFactory.getLog(UtilidadSistemaOperativo.class);

	public final static String[] WINDOWS4_NAMES = {"Windows 95", "Windows 98", "Windows 2000", "Windows NT"};
	public final static String[] WINDOWS_VERSIONS = { "4", "5" };
	public final static String[] LINUX_VERSIONS = {"2.4", "2.6"};
	public enum OS_NAMES { UNKNOWN, WINDOWS, LINUX};
	public enum OS_BITS { UNKNOWN, OS32BITS, OS64BITS};
	public enum SO {
		UNKNOWN(OS_NAMES.UNKNOWN, "", OS_BITS.UNKNOWN),
		WIN_4_32(OS_NAMES.WINDOWS, WINDOWS_VERSIONS[0], OS_BITS.OS32BITS),
		WIN_4_64(OS_NAMES.WINDOWS, WINDOWS_VERSIONS[0], OS_BITS.OS64BITS),
		WIN_5_32(OS_NAMES.WINDOWS, WINDOWS_VERSIONS[1], OS_BITS.OS32BITS),
		WIN_5_64(OS_NAMES.WINDOWS, WINDOWS_VERSIONS[1], OS_BITS.OS64BITS),
		LIN_24_32(OS_NAMES.LINUX, LINUX_VERSIONS[0], OS_BITS.OS32BITS),
		LIN_24_64(OS_NAMES.LINUX, LINUX_VERSIONS[0], OS_BITS.OS64BITS),
		LIN_26_32(OS_NAMES.LINUX, LINUX_VERSIONS[1], OS_BITS.OS32BITS),
		LIN_26_64(OS_NAMES.LINUX, LINUX_VERSIONS[1], OS_BITS.OS64BITS);
		
		private OS_NAMES osvalue;
		private String version;
		private OS_BITS bits;
		
		SO(OS_NAMES osvalue, String version, OS_BITS bits) {
			this.osvalue = osvalue;
			this.version = version;
			this.bits = bits;
		}
		public boolean isWindows() {
			if (osvalue.equals(OS_NAMES.WINDOWS))
				return true;
			return false;
		}
		public boolean isLinux() {
			if (osvalue.equals(OS_NAMES.LINUX))
				return true;
			return false;
		}
		public boolean is32bits() {
			if (bits.equals(OS_BITS.OS32BITS))
				return true;
			return false;
		}
		public boolean is64bits() {
			if (bits.equals(OS_BITS.OS64BITS))
				return true;
			return false;
		}
		public String getVersion() {
			return version;
		}
	}
	
	private static SO actualSO = injectSO();  
	private static SO injectSO() {
		// Obtiene el sistema operativo de las propiedades de sistema
		// TODO: obtención del numero de bits del SO
		String osName = getProperty(ConstantesXADES.OS_NAME);
        if (osName.toLowerCase().startsWith(ConstantesXADES.WIN)) {
        	if ((osName.startsWith(WINDOWS4_NAMES[0])) || (osName.startsWith(WINDOWS4_NAMES[1])) || 
        		(osName.startsWith(WINDOWS4_NAMES[2])) || (osName.startsWith(WINDOWS4_NAMES[3])))
        		return SO.WIN_4_32;
        	else
        		return SO.WIN_5_32;
        }
        else if (osName.toLowerCase().startsWith(ConstantesXADES.LINUX)) {
        	String osVersion = getProperty(ConstantesXADES.OS_VERSION);
        	if (osVersion.startsWith(LINUX_VERSIONS[0]))
        		return SO.LIN_24_32;
        	else if (osVersion.startsWith(LINUX_VERSIONS[1]))
        		return SO.LIN_26_32;
        	else 
        		return SO.UNKNOWN;
        }
		return SO.UNKNOWN;
	}
	
	/**
	 * Devuelve el sistema operativo en el que se ejecuta la aplicación
	 * @return elemento del enumerado con los datos del sistema operativo
	 */
	public static SO getSO() {
		return actualSO;
	}
    
    /**
     * Devuelve si es un plugin de Java
     * @return Verdadero o Falso
     */
	public static boolean javaplugin = false;
    static {
        String pluginVersion = getProperty(ConstantesXADES.JAVAPLUGIN_VERSION);
        if (pluginVersion != null)
            javaplugin = true;
    }
    
    /**
     * Devuelve si es linux
     * @return Verdadero o Falso
     */
    public static boolean isOSLinux() {
        if (getProperty(ConstantesXADES.OS_NAME).toLowerCase().startsWith(ConstantesXADES.LINUX))
            return true;
        return false;
    }
    
    /**
     * Devuelve si es windows
     * @return True o false
     */
    public static boolean isOSWindows() {
        if (getProperty(ConstantesXADES.OS_NAME).toLowerCase().startsWith(ConstantesXADES.WIN))
            return true;
        return false;
    }
    
    /**
     * Obtiene el directorio raíz del usuario
     * @return directorio raíz del usuario
     */
    public static String getUserHome() {
        String home = getProperty(ConstantesXADES.USER_HOME);
        if (isOSWindows()) {
            // encontrar la unidad de instalación
            String path = home.substring(0, home.indexOf(ConstantesXADES.BACK_SLASH));
            return path.replace('\\', '/');
        } else
            return home;
    }
    
    /**
     * Devuelve el nombre del usuario
     * @return Nombre del usuario
     */
    public static String getUserName() {
        return getProperty(ConstantesXADES.USER_NAME);
    }
    
    /**
     * Devuelve el separador de ficheros
     * @return caracter de separacion de ficheros
     */
    public static String getFileSeperator() {
        if (isOSWindows())
            return getProperty(ConstantesXADES.FILE_SEPARATOR).replace('\\', '/');
        else
            return getProperty(ConstantesXADES.FILE_SEPARATOR);
    }
    
    /**
     * Devuelve el directorio temporal
     * @return directorio temporal
     */
    public static String getTempDir() {
        return getProperty(ConstantesXADES.TMP_DIR);
    }
    
    /**
     * Devuelve el directorio Home
     * @return directorio Home 
     */
    public static String getHomeDir() {
        return getUserHome();
    }
    
    
    
    /**
     * @return boolean Verdadero si PKCS12 es un algoritmo que esta instalado
     */
    public static boolean hasPKCS12() {
        try {
            try {
                KeyStore.getInstance(ConstantesXADES.PKCS12);
            } catch (Throwable t) {
                return false;
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Lectura de la característica del sistema asegurada por un manager de la seguridad
     * El método maneja los 3 diferentes tipos manager de la seguridad:
     * Microsoft native JVM usando com.ms.security.*
     * Netscape or Java 1 security manager isamdp netscape.security.*
     * Plugin or Java 2 security managers usando AccessController.doPriviledge()
     * @param clave propiedad del sistema
     * @return Read propiedad del sistema
     */
    public static String getProperty(final String clave) {
        return System.getProperty(clave);
    }
    
    /**
     * Lectura de las propiedades del sistema
     * @return Read system properties
     */
    public static Properties getProperties() {
        return System.getProperties();
    }
    
}
