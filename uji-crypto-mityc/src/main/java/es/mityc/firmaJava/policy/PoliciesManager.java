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

package es.mityc.firmaJava.policy;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Manager que gestiona las instancias de validadores de policies.
 * 
 *  Diseñado como singleton.
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class PoliciesManager implements ConstantesXADES {
	
	private static final Log logger = LogFactory.getLog(PoliciesManager.class);
	
	private static PoliciesManager instance;
	private ResourceBundle props = null;
	
	private final static String POLICY_FILE_CONF = "policy";
	

	/**
	 * Constructor.
	 *
	 */
	private PoliciesManager() {
		// Carga las propiedades
		try {
			props = ResourceBundle.getBundle(POLICY_FILE_CONF);
		} catch (MissingResourceException ex) {
			logger.error(LIBRERIAXADES_POLICY_MANAGER_NO_FILE);
		}
	}
	
	/**
	 * Para evitar problemas de sincronismo se instancia la primera vez que se referencia
	 */
	static {
		instance = getInstance();
	}
	
	/**
	 * Devuelve una instancia del manager de policies.
	 *  
	 * @return
	 */
	public static PoliciesManager getInstance() {
		if (instance == null) {
			instance = new PoliciesManager();
		}
		return instance;
	}
	
	/**
	 * Devuelve el validador de policy asociado a la clave indicada. Funciona como una factory que instancia un nuevo validador en cada
	 * llamada.
	 *  
	 * @param clave Clave que tiene asociada un validador
	 * @return Una instancia del validador de policy asociado o <code>null</code> si no hay ninguno asociado o no se puede instanciar.
	 * 
	 * TODO: permitir funcionar a la factory en varios modos de trabajo (instanciador, cache, singleton, instanciador propio del validador)
	 */
	public IValidacionPolicy getValidadorPolicy(String clave) {
		IValidacionPolicy policyManager = null;
		if (props != null) {
			try {
				String classname = props.getString(clave);
				if (classname != null) {
					try {
						policyManager = (IValidacionPolicy)Class.forName(classname).newInstance();
					} catch (InstantiationException e) {
						logger.error(LIBRERIAXADES_POLICY_MANAGER_NO_INSTANCIA + clave + COMA_ESPACIO + classname + CIERRA_PARENTESIS, e);
					} catch (IllegalAccessException e) {
						logger.error(LIBRERIAXADES_POLICY_MANAGER_NO_PERMISOS + clave + COMA_ESPACIO + classname + CIERRA_PARENTESIS, e);
					} catch (ClassNotFoundException e) {
						logger.error(LIBRERIAXADES_POLICY_MANAGER_NO_CLAVE + clave + COMA_ESPACIO + classname + CIERRA_PARENTESIS, e);
					} catch (ClassCastException e) {
						logger.error(LIBRERIAXADES_POLICY_MANAGER_NO_TIPO + clave + COMA_ESPACIO + classname + CIERRA_PARENTESIS, e);
					}
				}
			} catch (MissingResourceException ex) {
				logger.error(LIBRERIAXADES_POLICY_MANAGER_NO_VALIDADOR + clave);
			}
		}
		return policyManager;
	}
	
	/**
	 * Devuelve el escritor de policy asociado a la clave indicada. Funciona como una factory que instancia un nuevo escritor en cada
	 * llamada.
	 *  
	 * @param clave Clave que tiene asociada un escritor
	 * @return Una instancia del escritor de policy asociado o <code>null</code> si no hay ninguno asociado o no se puede instanciar.
	 * 
	 * TODO: permitir funcionar a la factory en varios modos de trabajo (instanciador, cache, singleton, instanciador propio del escritor)
	 */
	public IFirmaPolicy getEscritorPolicy(String clave) {
		IFirmaPolicy policyManager = null;
		if (props != null) {
			try {
				String classname = props.getString(clave);
				if (classname != null) {
					try {
						policyManager = (IFirmaPolicy)Class.forName(classname).newInstance();
					} catch (InstantiationException e) {
						logger.error(ConstantesXADES.LIBRERIAXADES_POLICY_MANAGER_NO_INSTANCIA + clave + ConstantesXADES.COMA_ESPACIO + classname + ConstantesXADES.CIERRA_PARENTESIS, e);
					} catch (IllegalAccessException e) {
						logger.error(ConstantesXADES.LIBRERIAXADES_POLICY_MANAGER_NO_PERMISOS + clave + ConstantesXADES.COMA_ESPACIO + classname + ConstantesXADES.CIERRA_PARENTESIS, e);
					} catch (ClassNotFoundException e) {
						logger.error(ConstantesXADES.LIBRERIAXADES_POLICY_MANAGER_NO_CLAVE + clave + ConstantesXADES.COMA_ESPACIO + classname + ConstantesXADES.CIERRA_PARENTESIS, e);
					} catch (ClassCastException e) {
						logger.error(ConstantesXADES.LIBRERIAXADES_POLICY_MANAGER_NO_TIPO + clave + ConstantesXADES.ESPACIO + classname + ConstantesXADES.CIERRA_PARENTESIS, e);
					}
				}
			} catch (MissingResourceException ex) {
				logger.error(ConstantesXADES.LIBRERIAXADES_POLICY_MANAGER_NO_VALIDADOR + clave);
			}
		}
		return policyManager;
	}

}
