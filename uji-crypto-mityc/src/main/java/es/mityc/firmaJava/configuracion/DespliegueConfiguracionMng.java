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

package es.mityc.firmaJava.configuracion;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Clase para la gestión de configuraciones específicas de despliegue.
 * 
 * <br/><br/>
 * Mediante esta utilidad se puede tener preparados un conjunto de ficheros de propiedades según el tipo de despliegue
 * que se vaya a hacer del proyecto. Para utilizar una u otra configuración sólo habría que cambiar el fichero de propiedades
 * referenciado en el fichero de propiedades <code>despliegue.properties</code>.
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0 beta
 */

public class DespliegueConfiguracionMng {
	
	private static Log log = LogFactory.getLog(DespliegueConfiguracionMng.class);
	
	private static DespliegueConfiguracionMng instance;
	private ArrayList<ResourceBundle> props;
	
	private static final String ST_NO_RECURSOS_FILE = "No se ha encontrado el fichero de recursos";
	
	static {
		instance = new DespliegueConfiguracionMng();
	}
	
	/**
	 * Obtiene una instancia de la clase.
	 * @return instancia única de la clase
	 */
	public static DespliegueConfiguracionMng getInstance() {
		return instance;
	}
	
	/**
	 * Recarga la configuración
	 */
	public static synchronized void reloadConfiguration() {
		instance = new DespliegueConfiguracionMng();
	}
	
	/**
	 * Constructor.
	 * 
	 * Recupera los ficheros de configuración que se utilizarán para el despliegue 
	 */
	protected DespliegueConfiguracionMng() {
		try {
			ResourceBundle rb = ResourceBundle.getBundle(ConstantesConfiguracion.STR_DESPLIEGUE);
			String files = rb.getString(ConstantesConfiguracion.STR_DESPLIEGUE_CONF_FILE);
			if (files != null) {
				StringTokenizer st = new StringTokenizer(files, ConstantesConfiguracion.COMA);
				props = new ArrayList<ResourceBundle>(st.countTokens());
				boolean hasNext = st.hasMoreTokens();
				while (hasNext) {
					String file = st.nextToken();
					hasNext = st.hasMoreTokens();
					try {
						props.add(ResourceBundle.getBundle(file));
					} catch (MissingResourceException ex) {
						log.debug(ST_NO_RECURSOS_FILE + ConstantesConfiguracion.ESPACIO + file);
					}
				}
			}
		} catch (MissingResourceException ex) {
			log.debug(ConstantesConfiguracion.STR_RECURSO_NO_DISPONIBLE, ex);
		}
	}
	
	/**
	 * Busca el valor asociado a una clave a través de todos los ficheros de propiedades configurados.
	 * @param key clave
	 * @return Devuelve el primer valor asociado encontrado o <code>null</code> si no hay ninguno 
	 */
	protected String getValue(String key) {
		// Pese a los problemas de sincronismo, se accede a esta lista sin sincronización porque se supone
		// que la estructura no se cambia una vez instanciada la clase o en una recarga (ya sincronizada).
		String value = null;
		// OPTIMIZACION: pasar a otro sistemas de propiedades más eficiente que un conjunto de resourcebundle (por ejemplo un único Properties integral con todas las propiedades)
		if (props != null) {
			Iterator<ResourceBundle> it = props.iterator();
			boolean hasNext = it.hasNext();
			while (hasNext) {
				try {
					value = it.next().getString(key);
					hasNext = it.hasNext();
				} catch(MissingResourceException ex) {
					// Continua con el bucle
					continue;
				}
				break;
			}
		}
		return value;
	}
	
	/**
	 * Recupera la cadena asociada con la clave indicada
	 * @param key clave
	 * @return cadena asociada, <code>null</code> si no hay cadena asociada
	 */
	public String getString(String key) {
		return getValue(key);
	}
	
	/**
	 * Recupera el boolean asociado a la clave indicada
	 * @param key clave
	 * @return boolean asociado, <code>false</code> si no hay cadena asociada
	 */
	public boolean getBoolean(String key) {
		boolean value = false;
		if (props != null) {
			try {
				value = Boolean.parseBoolean(getValue(key));
			} catch (MissingResourceException ex) {
				log.debug(ConstantesConfiguracion.STR_RECURSO_NO_DISPONIBLE, ex);
			}
		}
		return value;
	}

}
