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


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.errores.PolicyException;
import es.mityc.firmaJava.policy.ConstantesFacturaePolicy;

/**
 * Implementación de la política de factura electrónica v 3.0:
 * http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */
public class Facturae30Manager extends FacturaeManager {
	private final static Log logger = LogFactory.getLog(Facturae30Manager.class);
	
	private static final String PREFIX_POLICY_PROP = "facturae30";
	private static ConfigFacturae config = null;
	
	static {
		try {
			config = FacturaeManager.loadConfig(PREFIX_POLICY_PROP);
		} catch (ConfigFacturaeException ex) {
			logger.fatal("No se pudo cargar la configuracion del validador",ex);
		}
	}
	
	public Facturae30Manager() throws InstantiationException {
		if (config == null)
			throw new InstantiationException("No hay configuración disponible");
	}

	public String getIdentidadPolicy() {
		return config.policyIdValidador;
	}

	/**
	 * Valida que se cumpla la policy especificada en el documento:
	 * http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf
	 * 
	 * <p>Detalles para firma básica:<ul>
	 *   <li>La firma ha de ser enveloped</li>
	 *   <li>El certificado firmante ha de estar en un elemento KeyInfo</li>
	 *   <li>El rol debe estar vacío, o ser de tipo ClaimedRol y contener uno de los siguientes valores:<ul>
	 *     <li>"emisor" o "supplier" si la firma la realiza el emisor</li>
	 *     <li>"receptor" o "customer" si la firma la realiza el receptor</li>
	 *     <li>"tercero" o "third party" si la firma la realiza una persona o entidad distinta al emisor o receptor de la factura</li>
	 *     Este validador sólo comprobará que la semántica de los nombres es la correcta.
	 *   </ul></li>
	 *   <li>Que haya un elemento SignaturePolicyIdentifier (XADES-EPES) con los valores:<ul>
	 *     <li><xades:SigPolicyId><xades:Identifier>http://www.facturae.es/politica de firma formato facturae/politica de firma formato facturae v3_0.pdf</xades:Identifier></xades:SigPolicyId></li>
	 *     <li>la huella digital del documento de policy en un elemento <xades:SigPolicyHash>
	 *   </ul></li>
	 *   <li>Si la firma es <i>menor</i> a XADES-C (no contiene información de validación) validar el certificado firmante. Este validador no implementa esta característica</li>
	 * </ul></p>
	 * Detalles para firma avanzada (XADES-XL):<ul>
	 *   <li>El sello de tiempo debe estar a menos de tres días de la fecha del campo xades:SigningTime y no puede superar a la fecha de caducidad del certificado firmante</li>
	 *   <li>La información del estado del certificado firmante ha de ser posterior a 24 después de la fecha indicada en SigningTime</li>
	 *   <li>La ruta de certificación ha de ser completa</li>
	 * </ul>
	 * <p>Certificados electrónicos:<ul>
	 *   <li>Los certificados han de cumplir lo indicado en los apartados a) ó c) del artículo 18 del Reglamento que está recogido en R.D. 1496/2003 del 28 de Noviembre.
	 *       Este validador no implementa esta comprobación</li>
	 * </ul></p>
	 * <p>Sellos de tiempo:<ul>
	 *   <li>Se admiten los sellos de tiempo expedidos por aquellas Autoridades de Sellado de Tiempo que cumplan con la norma ETSI TS 102 023 "Policy requirements for time-stamping authorities".
	 *       Este validador no implementa esta comprobación.</li>
	 * </ul></p>
	 * 
	 */
	public void validaPolicy(Element nodoFirma, final ResultadoValidacion resultadoValidacion) throws PolicyException {
		if (!isValidSchema(nodoFirma, resultadoValidacion)) {
			throw new PolicyException ("Versión de esquema XAdES no permitido");
		}
		
		if (!isValidPolicyHash(nodoFirma, resultadoValidacion, config)) {
			throw new PolicyException ("Huella de la política incorrecta");
		}

		if (!isEnveloped(nodoFirma, resultadoValidacion)) {
			throw new PolicyException (I18n.getResource(ConstantesFacturaePolicy.ERROR_POLICY_GENERICO_01) + ConstantesFacturaePolicy.ESPACIO + I18n.getResource(ConstantesFacturaePolicy.ERROR_NOT_ENVELOPED));
		}
		
		if (!isCertificateInKeyInfoNode(nodoFirma, resultadoValidacion)) {
			throw new PolicyException (I18n.getResource(ConstantesFacturaePolicy.ERROR_POLICY_GENERICO_01) + ConstantesFacturaePolicy.ESPACIO + I18n.getResource(ConstantesFacturaePolicy.ERROR_KEYINFO_POLICY));
		}
		if (!isValidRole(nodoFirma, resultadoValidacion)) {
			throw new PolicyException (I18n.getResource(ConstantesFacturaePolicy.ERROR_POLICY_GENERICO_01) + ConstantesFacturaePolicy.ESPACIO + I18n.getResource(ConstantesFacturaePolicy.ERROR_ROLE_POLICY));
		}
		
		comprobarTimestamp(nodoFirma);
		
		comprobarInfoCertificado(nodoFirma);
		
		comprobarCertificadoConfianza(nodoFirma);
		
		comprobarTsaConfianza(nodoFirma);
	}
	
	/**
	 * Comprueba que el esquema de la firma es el esperado
	 * 
	 * @param nodoFirma
	 * @param rs
	 * @return <code>true</code> si el esquema es el válido, <code>false</code> en otro caso
	 */
	protected boolean isValidSchema(Element nodoFirma, final ResultadoValidacion rs) {
		XAdESSchemas schema = rs.getDatosFirma().getEsquema();
		if (XAdESSchemas.XAdES_122.equals(schema))
			return true;
		return false;
	}
	
	/**
	 * @see es.mityc.firmaJava.policy.IFirmaPolicy#escribePolicy(org.w3c.dom.Element, java.lang.String, java.lang.String, es.mityc.firmaJava.libreria.xades.XAdESSchemas)
	 */
	public void escribePolicy(Element nodoFirma, String namespaceDS, String namespaceXAdES, XAdESSchemas schema) throws PolicyException {
		escribePolicy(nodoFirma, namespaceDS, namespaceXAdES, schema, config);
	}

}
