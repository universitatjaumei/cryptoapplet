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
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
 * 
 */
package es.mityc.firmaJava.policy;

import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.libreria.xades.elementos.DigestAlgAndValueType;
import es.mityc.firmaJava.libreria.xades.elementos.SigPolicyHash;
import es.mityc.firmaJava.libreria.xades.elementos.SigPolicyId;
import es.mityc.firmaJava.libreria.xades.elementos.SignaturePolicyIdentifier;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;
import es.mityc.firmaJava.libreria.xades.errores.PolicyException;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public abstract class FacturaeManager implements IValidacionPolicy, IFirmaPolicy {
	
	private static final Log logger = LogFactory.getLog(FacturaeManager.class);
	
	private static ResourceBundle rb = null;
	
	static {
		try {
			rb = ResourceBundle.getBundle(ConstantesFacturaePolicy.RESOURCEBUNDLE_NAME);
		} catch (MissingResourceException ex) {
			logger.fatal("No se ha podido cargar fichero de configuración de validadores de facturae", ex);
		}
	}

	protected static synchronized ConfigFacturae loadConfig(String prefix) throws ConfigFacturaeException {
		if (rb == null)
			throw new ConfigFacturaeException("No hay fichero de configuración disponible");
		return new ConfigFacturae(rb, prefix);
	}
	
	/**
	 * Devuelve el DigestAlgAndValueType de la configuración que esté relacionado con el algoritmo indicado.
	 * 
	 * @param algorithm
	 * @return <code>null</code> si no se encuentra ningún digest asociado al algoritmo
	 */
	private DigestAlgAndValueType getDigestRelated(String algorithm, ConfigFacturae config) {
		DigestAlgAndValueType daavt = null;
		Iterator<DigestAlgAndValueType> it = config.huellas.iterator();
		while (it.hasNext()) {
			DigestAlgAndValueType temp = it.next();
			if (temp.getMethod().getAlgorithm().equals(algorithm)) {
				daavt = temp;
				break;
			}
		}
		return daavt;
	}
	
	/**
	 * Comprueba los hashes de la policy del documento de firma
	 * @param nodo
	 * @return true si son validos
	 */
	protected boolean isValidPolicyHash (Element nodoFirma, final ResultadoValidacion rs, ConfigFacturae config)  {
		XAdESSchemas schema = rs.getDatosFirma().getEsquema();
		if (schema == null)
			return false;
		String esquema = schema.getSchemaUri();

		// Nodo SignaturePolicyIdentifier
		NodeList signaturePolicyList = nodoFirma.getElementsByTagNameNS(esquema, ConstantesXADES.SIGNATURE_POLICY_IDENTIFIER);
		if (signaturePolicyList.getLength() != 1)
			return false;
		if (signaturePolicyList.item(0).getNodeType() != Node.ELEMENT_NODE)
			return false;

		
		try {
			SignaturePolicyIdentifier signaturePolicyIdentifier = new SignaturePolicyIdentifier(schema);
			if (!signaturePolicyIdentifier.isThisNode(signaturePolicyList.item(0)))
				throw new InvalidInfoNodeException("No se ha encontrado política");
			signaturePolicyIdentifier.load((Element)signaturePolicyList.item(0));
			
			if (signaturePolicyIdentifier.isImplied())
				throw new InvalidInfoNodeException("La política encontrada es implícita");
			
			DigestAlgAndValueType value = getDigestRelated(signaturePolicyIdentifier.getSignaturePolicyId().getSigPolicyHash().getMethod().getAlgorithm(), config);
			SignaturePolicyIdentifier comp = createPolicy(schema, config, value);
			
			if (!signaturePolicyIdentifier.equals(comp))
				return false;
		} catch (InvalidInfoNodeException ex) {
			if (logger.isDebugEnabled())
				logger.debug("Error obteniendo digest/value de la policy", ex);
			return false;
		}
		return true;
	}
	
	// AppPerfect: Todos estos métodos sin implementar dan un falso positivo: Declare_methods_not_using_instance_members_static
	
	/**
	 * Comprueba si la firma es enveloped
	 * @param nodo
	 * @return true si es enveloped
	 */
	protected boolean isEnveloped (Element nodo, final ResultadoValidacion rs) {
		//	TODO: que la firma sea enveloped (un reference tiene que ser con uri "")
		
		return true;
	}
	
	/**
	 * Comprueba que el certificado de firma esta dentro del nodo keyInfo
	 * @param nodo
	 * @return
	 */
	protected boolean isCertificateInKeyInfoNode (Element nodo, final ResultadoValidacion rs) {
		//	TODO: que el certificado de firma esté en un elemento KeyInfo
		
		return true;
	}
	
	/**
	 * Comprueba que el role de firma (si existe) es aceptado por la policy
	 * @param nodo
	 * @return
	 */
	protected boolean isValidRole (Element nodo, final ResultadoValidacion rs) {
		// TODO: que se ajuste al rol esperado
		
		return true;
	}


	/**
	 * Si es una firma XAdES-XL se comprueba lo siguiente:
	 * <ul>
	 * <li>Que los sellos de tiempo sean no posteriores a tres días después de la firma</li>
	 * <li>Que sean previos a la caducidad del certificado</li>
	 * </ul> 
	 * @param nodoFirma
	 * @throws PolicyException Si la informacion obtenida no corresponde con la policy o no se pudo comprobar
	 */
	protected void comprobarTimestamp(Element nodoFirma) throws PolicyException {
		//	TODO LARGO: si es firma XL que los sellos de tiempo sean no posteriores a tres días después de la firma y previos a la caducidad del certificado
		
	}

	/**
	 * Si es una firma XAdES-XL se comprueba que la información OCSP/CRL sea mínimo 24 horas posterior a la realización de la firma.
	 * @param nodoFirma
	 * @throws PolicyException Si la informacion obtenida no corresponde con la policy o no se pudo comprobar
	 */
	protected void comprobarInfoCertificado(Element nodoFirma) throws PolicyException  {
		// TODO LARGO: si es firma XL que la información OCSP/CRL sea mínimo 24 horas posterior a la realización de la firma

		
	}

	/**
	 * Se comprueba que el certificado firmante es de confianza.
	 * @param nodoFirma
	 * @throws PolicyException Si la informacion obtenida no corresponde con la policy o no se pudo comprobar
	 */
	protected void comprobarCertificadoConfianza(Element nodoFirma) throws PolicyException  {
		// TODO LARGO: chequeo de que el certificado firmante es de confianza (según la ley)
		
		
	}

	/**
	 * Se comprueba que la TSA utilizada es de confianza.
	 * @param nodoFirma
	 * @throws PolicyException Si la informacion obtenida no corresponde con la policy o no se pudo comprobar
	 */
	protected void comprobarTsaConfianza(Element nodoFirma)  throws PolicyException {
		// TODO LARGO: chequeo de que la TSA es de confianza
		
	}
	
	protected SignaturePolicyIdentifier createPolicy(XAdESSchemas schema, ConfigFacturae config, DigestAlgAndValueType value) throws InvalidInfoNodeException {
		if (value == null) {
			throw new InvalidInfoNodeException("Algoritmo de hash de la policy no soportado");
		}
		
		SignaturePolicyIdentifier resultado = new SignaturePolicyIdentifier(schema, false);
		resultado.getSignaturePolicyId().setSigPolicyId(new SigPolicyId(schema, config.policyIdXades, config.policyDescription));
		resultado.getSignaturePolicyId().setSigPolicyHash(new SigPolicyHash(schema, value));
		return resultado;
	}
	
	/**
	 * @see es.mityc.firmaJava.policy.IFirmaPolicy#escribePolicy(org.w3c.dom.Element, java.lang.String, java.lang.String, es.mityc.firmaJava.libreria.xades.XAdESSchemas)
	 */
	public void escribePolicy(Element nodoFirma, String namespaceDS, String namespaceXAdES, XAdESSchemas schema, ConfigFacturae config) throws PolicyException {
		// Crea el nodo de política
		SignaturePolicyIdentifier spi;
		try {
			if ((config.policyWriterId < 0) || (config.policyWriterId >= config.huellas.size()))
				throw new InvalidInfoNodeException("Configuración inadecuada para escribir la policy");
			DigestAlgAndValueType hash = config.huellas.get(config.policyWriterId);
			
			spi = createPolicy(schema, config, hash);
		} catch (InvalidInfoNodeException ex) {
			throw new PolicyException("Error en la configuración de escritura de la policy");
		}
		UtilidadPolitica.escribePolicy(nodoFirma, namespaceDS, namespaceXAdES, schema, spi);
	}

	

}
