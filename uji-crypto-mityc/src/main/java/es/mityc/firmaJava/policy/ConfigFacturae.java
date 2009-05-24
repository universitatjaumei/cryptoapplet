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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.firmaJava.libreria.xades.elementos.DigestAlgAndValueType;
import es.mityc.firmaJava.libreria.xades.elementos.SigPolicyHash;

/**
 * Esta clase centraliza la configuración de funcionamiento de un validador de política de factura-e
 *  
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public class ConfigFacturae {
	
	private static Log logger = LogFactory.getLog(ConfigFacturae.class);

	/** Identificador de la policy que se espera encontrar en la firma */
	public URI policyIdXades = null;
	/** Cadena de identificación de la policy */ 
	public String policyIdValidador = null;
	/** Cadena de descripción de la policy */
	public String policyDescription = null;
	/** Hash's que se consideran válidos de la policy */
	public ArrayList<DigestAlgAndValueType> huellas = null;
	/** Número de digest que utilizar para el escritor de policy */
	public int policyWriterId = -1;

	
	public ConfigFacturae(ResourceBundle props, String prefix) throws ConfigFacturaeException {
		String prep = "";
		if ((prefix != null) && (!"".equals(prefix.trim())))
			prep = prefix + ".";
		// carga los datos de identidad
		try  {
			policyIdXades = new URI(props.getString(prep + ConstantesFacturaePolicy.PROPNAME_POLICY_ID));
			policyIdValidador = props.getString(prep + ConstantesFacturaePolicy.PROPNAME_POLICY_ID_VALIDADOR);
		} catch (MissingResourceException ex) {
			logger.fatal("Error en la carga de la configuración del validador de facturae");
			throw new ConfigFacturaeException("Error en la configuración", ex);
		} catch (URISyntaxException ex) {
			logger.fatal("Identificador de la policy indicada inválido");
			throw new ConfigFacturaeException("Error en la configuración", ex);
		}
		// carga la descripcion de la policy
		try  {
			policyDescription = props.getString(prep + ConstantesFacturaePolicy.PROPNAME_POLICY_ID_VALIDADOR);
		} catch (MissingResourceException ex) {
			if (logger.isTraceEnabled())
				logger.trace("No hay descripción para esta policy: " + prep);
		}
		// Carga la huellas
		huellas = new ArrayList<DigestAlgAndValueType>();
		int i = 0;
		while (true) {
			try {
				huellas.add(new SigPolicyHash(null,
						props.getString(prep + ConstantesFacturaePolicy.PROPNAME_HASH_ID + i),
						props.getString(prep + ConstantesFacturaePolicy.PROPNAME_HASH_VALUE + i)));
				i++;
			} catch (MissingResourceException ex) {
				break;
			}
		}
		// carga el número de hash que se utilizará en el escritor 
		try  {
			policyWriterId = Integer.parseInt(props.getString(prep + ConstantesFacturaePolicy.PROPNAME_WRITER_HASH));
			if (policyWriterId >= huellas.size()) {
				policyWriterId = -1;
				logger.error("Error al indicar número de hash a escribir");
			}
		} catch (MissingResourceException ex) {
			if (logger.isTraceEnabled())
				logger.trace("No hay indicado hash para el escritor: " + prep);
		} catch (NumberFormatException ex) {
			logger.error("Error al indicar número de hash a escribir", ex);
		}
	}
	

}
