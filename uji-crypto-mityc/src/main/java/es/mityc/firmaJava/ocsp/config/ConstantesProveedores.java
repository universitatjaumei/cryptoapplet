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

package es.mityc.firmaJava.ocsp.config;

/** 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public interface ConstantesProveedores {
	static final Object NODO_PROVEEDORES = "proveedores";
	static final Object NODO_VERSION = "version";
	static final Object NODO_FECHA = "fecha";
	static final Object NODO_PROVEEDOR = "proveedor";
	static final Object NODO_CA = "ca";
	static final Object NODO_OCSP = "servidorOCSP";
	static final String ATT_NOMBRE = "nombre";
	static final String ATT_NAMEHASH = "nameHash";
	static final String ATT_PKHASH = "pkHash";
	static final String ATT_DESCRIPCION = "descripcion";
	static final String ATT_URI = "URI";
	static final String FEATURE_NAMESPACES = "http://xml.org/sax/features/namespaces";
	static final String FEATURE_VALIDATION = "http://xml.org/sax/features/validation";
	static final String FEATURE_SCHEMA = "http://apache.org/xml/features/validation/schema";
	static final String FEATURE_EXTERNALSCHEMA = "http://apache.org/xml/properties/schema/external-schemaLocation";
	static final String XML_FILE = "OCSPServersInfo.xml";
	static final String XSD_FILE = "OCSPServersInfo.xsd";
	static final String SEPARATOR = "/";
	static final String EMPTY_STRING = "";
	static final String ALMOHADILLA = "#";
	static final String XML_DEFAULT_FILE = SEPARATOR + XML_FILE;
	static final String XSD_DEFAULT_FILE = SEPARATOR + XSD_FILE;
	static final String USERDIR = "user.dir";
	static final String IO_EXCEPTION = "IOException ";
	static final String CERTIFICATE_EXCEPTION = "IOException ";
	static final String INVALID_URI = "Invalid Uri. ";
	static final String CERTIFICATE_TYPE_EXCEPTION = "Illegal argument type. Can be a String, byte[] or X509Certificate.";
	static final String X_509 = "X.509";
}
