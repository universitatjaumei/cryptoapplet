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

/** 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public interface ConstantesFacturaePolicy {

	public final static String PROPNAME_HASH_ID = "policy.digest.id.";
	public final static String PROPNAME_HASH_VALUE = "policy.digest.value.";
	public final static String PROPNAME_SCHEMA_URI = "xades.schema.uri.";
	public final static String PROPNAME_POLICY_ID = "policy.id";
	public final static String RESOURCEBUNDLE_NAME = "facturae";
	public final static String PROPNAME_POLICY_ID_VALIDADOR = "policy.idValidator";
	public final static String PROPNAME_POLICY_DESCRIPTION = "policy.description";
	public final static String PROPNAME_WRITER_HASH = "policy.writer.digest";

	public static final String ERROR_POLICY_GENERICO_01 = "libreriapolicy.error1";
	public static final String ERROR_NOT_ENVELOPED = "libreriapolicy.error2";
	public static final String ERROR_ROLE_POLICY = "libreriapolicy.error3";
	public static final String ERROR_KEYINFO_POLICY  = "libreriapolicy.error4";
	
	// Constantes para la policy
	public static final String ESPACIO = " ";
	 

	public static final String ES_MINUSCULA = "es";
	public static final String ES_MAYUSCULA = "ES";
	public static final String NOMBRE_LIBRERIA = "i18n_LibreriaPolicy";
	public static final String LOCALE = "locale";

}
