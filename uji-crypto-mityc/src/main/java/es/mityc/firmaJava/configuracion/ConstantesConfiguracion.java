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

/** 
* @author  Ministerio de Industria, Turismo y Comercio
* @version 1.0 beta
*/

public interface ConstantesConfiguracion {

	public static final String VALOR_NO = "N";
	public static final String VALOR_YES = "Y";
	/**
	 * Valor por defecto para XML_SN
	 */
	public static final String VALOR_XML_SN 				= "ds";
	/**
	 * Valor por defecto para XML_XADES_NS
	 */
	public static final String VALOR_XML_XADES_NS 		= "etsi";
	/**
	 * Valor por defecto para TIMESTAMP
	 */
	public static final String VALOR_TIMESTAMP			= VALOR_NO;
	/**
	 * Valor por defecto para XADES_C
	 */
//	public static final String VALOR_XADES_C				= VALOR_NO;
	/**
	 * Valor por defecto para XADES_X
	 */
//	public static final String VALOR_XADES_X				= VALOR_NO;
	/**
	 * Valor por defecto para XADES_L
	 */
//	public static final String VALOR_XADES_L				= VALOR_NO;
	/**
	 * Valor por defecto para IS_PROXY
	 */
	public static final String VALOR_IS_PROXY				= VALOR_NO;
	/**
	 * Valor por defecto para VALIDATE_OCSP
	 */
	public static final String VALOR_VALIDATE_OCSP		= VALOR_NO;
	/**
	 * Valor por defecto para SAVE_SIGN
	 */
	public static final String VALOR_SAVE_SIGN			= VALOR_NO;
	/**
	 * Valor por defecto para ADD_XADES
	 */
//	public static final String VALOR_ADD_XADES			= VALOR_YES;
	/**
	 * Valor por defecto para XML_DSIG_SCHEMA
	 */
	public static final String VALOR_XML_DSIG_SCHEMA		= "http://www.w3.org/2000/09/xmldsig#";
	/**
	 * Valor por defecto para XADES_SCHEMA
	 */
	public static final String VALOR_XADES_SCHEMA			= "http://uri.etsi.org/01903/v1.3.2#";
	/**
	 * Valor por defecto para LOCALE
	 */
	public static final String VALOR_LOCALE				= "es";
	/**
	 * Valor por defecto para ENCODING_XML
	 */
	public static final String VALOR_ENCODING_XML			= "UTF-8";  

	public static final String VALOR_PKCS7                = VALOR_NO;
//	public static final String VALOR_XADES_T				= VALOR_NO;
//	public static final String VALOR_XADES_XL				= VALOR_NO;
	
	public static final String FICHERO_PROPIEDADES 	= "/SignXML.properties";
	public static final String FICHERO_RESOURCE 		= "SignXML";
	public static final String XMLNS = "xmlsn";
	public static final String XML_XADES_NS = "xmlXadesNS";
	public static final String PKCS7 = "pkcs7";
//	public static final String XADES_T = "Xades-T";
//	public static final String XADES_XL = "Xades-XL";
	public static final String IS_PROXY = "isProxy";
	public static final String VALIDATE_OCSP = "validateOCSP";
	public static final String SAVE_SIGN = "SaveSign";
	public static final String CONFIG_EXT = "ConfigExternAllowed";
	public static final String CONFIG_EXT_FILE = "ConfigExternFile";
	public static final String CONFIG_EXT_DIR = "ConfigExternDir";
	
//	public static final String ADD_XADES = "addXades";
	
	public static final String XML_DSIG_SCHEMA = "xmldsigSchema";
	public static final String XADES_SCHEMA = "xadesSchema";
	public static final String LOCALE = "locale";
	public static final String ENCODING_XML = "encodingXML";
	public static final String CARGA_CONFIGURACION_DEFECTO = "Se carga la configuración por defecto"; 
	public static final String COMPRUEBA_PERMISO_FICHERO_EXT = "Se comprueba si se puede utilizar fichero externo de propiedades";
	public static final String NO_FORMATO_XADES = "Fichero de configuracion: No se indico ningun formato XAdES. Se usa formato por defecto: XAdES-BES";
	public static final String KEY = "Key: ";
	public static final String VALUE = " Value: ";
	
	public static final String CRLF = "\n";
	public static final String USER_DIR = "user.dir";
	public static final String USER_HOME = "user.home";
	public static final String IGUAL = "=";
	public static final String IGUAL_ESPACIADO = " = ";
	public static final String ESPACIO = " ";
	public static final String COMA = ",";
	
	public static final String CADENA_VACIA = "";
	public static final String ERROR_DOS_PUNTOS = "Error: ";
	
	public static final String IGUAL_NULL = "= null";
	
	public static final String SI_MINUSCULA = "s";
	public static final String YES_MINUSCULA = "y";
	/* ********************************* TEST ************************* */
	/* TEST */ 
	public static final String CFG_FORMATO_XADES = "FormatoXades";
	public static final String CFG_XMLSIGNATURE = "XMLSIGNATURE";
	public static final String CFG_XADES_BES = "XADES-BES";
	public static final String CFG_XADES_T = "XADES-T";
	public static final String CFG_XADES_C = "XADES-C";	
	public static final String CFG_XADES_X = "XADES-X";	
	public static final String CFG_XADES_XL = "XADES-XL"; 
	public static final String ADD_TSA = "addTSA";
	
	public static final String CFG_ALMACEN = "almacenCerts";
	public static final String CFG_ALMACEN_EXPLORER = "IEXPLORER";
	public static final String CFG_ALMACEN_MOZILLA = "MOZILLA";
	public static final String CFG_RUTA_PROFILE_MOZILLA = "rutaProfileMozilla";
	
	public static final String STR_DESPLIEGUE = "despliegue";
	public static final String STR_DESPLIEGUE_CONF_FILE = "despliegue.conf.file";
	public static final String STR_RECURSO_NO_DISPONIBLE = "Recurso no disponible";
	
}
