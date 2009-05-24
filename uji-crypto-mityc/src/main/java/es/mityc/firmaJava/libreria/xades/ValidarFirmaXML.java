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

package es.mityc.firmaJava.libreria.xades;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Authenticator;
import java.net.URLDecoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.keyresolver.KeyResolverException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.tsp.TSPException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import es.mityc.firmaJava.configuracion.Configuracion;
import es.mityc.firmaJava.configuracion.EnumFormatoFirma;
import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.Base64;
import es.mityc.firmaJava.libreria.utilidades.Base64Coder;
import es.mityc.firmaJava.libreria.utilidades.I18n;
import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.utilidades.SimpleAuthenticator;
import es.mityc.firmaJava.libreria.utilidades.UtilidadCertificados;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFechas;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFirmaElectronica;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.utilidades.Utilidades;
import es.mityc.firmaJava.libreria.xades.elementos.SignaturePolicyIdentifier;
import es.mityc.firmaJava.libreria.xades.errores.BadFormedSignatureException;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;
import es.mityc.firmaJava.libreria.xades.errores.InvalidInfoNodeException;
import es.mityc.firmaJava.libreria.xades.errores.PolicyException;
import es.mityc.firmaJava.ocsp.RespuestaOCSP;
import es.mityc.firmaJava.ocsp.RespuestaOCSP.TIPOS_RESPONDER;
import es.mityc.firmaJava.policy.IValidacionPolicy;
import es.mityc.firmaJava.policy.PoliciesManager;
import es.mityc.firmaJava.policy.PolicyResult;
import es.mityc.firmaJava.ts.TSCliente;
import es.mityc.firmaJava.ts.TSClienteError;
import es.mityc.firmaJava.ts.TSPAlgoritmos;
import es.mityc.firmaJava.ts.TSValidacion;

/**
 * Clase para la validación de la firmas XADES
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class ValidarFirmaXML implements ConstantesXADES
{
	private Configuracion 			configuracion 			=	null;

	private Document 				doc 					= 	null;
	private Element					firmaAValidar 			= 	null;
	private List<String>			esquemasParaValidar		= 	new LinkedList<String>();
	private String					esquema 				= 	null;

	private boolean 				esValido				= 	false;
	private ResultadoValidacion 	resultado				= 	new ResultadoValidacion();
	private DatosFirma 				datosFirma				=	null;
	private ArrayList<DatosSelloTiempo> arrayDatosSello		=   new ArrayList<DatosSelloTiempo>();
	private ArrayList<DatosCRL> 	arrayDatosCRL			=	new ArrayList<DatosCRL>();	
	private ArrayList<DatosOCSP> 	arrayDatosOCSP			=	new ArrayList<DatosOCSP> ();
	private ArrayList<PolicyResult> politicas 				= 	new ArrayList<PolicyResult> ();
	private ArrayList<X509Certificate> cadenaCertificados	=	new ArrayList<X509Certificate> ();

	private DatosTipoFirma			tipoDocFirma			= 	null;

	private static Log log = LogFactory.getLog(ValidarFirmaXML.class);
	
	protected class EstructuraFirma {
		String esquema;
		Element firma;
		Element signedSignatureProperties;
		Element unsignedSignatureProperties;
	}

	/**
	 * Crea una nueva instancia de ValidarFirmaXML
	 */
	public ValidarFirmaXML()
	{
		configuracion = new Configuracion();
		configuracion.cargarConfiguracion() ;
	}

	/**
	 * Crea una nueva instancia de ValidarFirmaXML con una configuración ya cargada
	 */
	public ValidarFirmaXML(Configuracion configuracion)
	{
		this.configuracion = configuracion;
	}

	/**
	 * Valida la firma XML
	 * @param firmaParaValidar firchero con la firma XADES para validar
	 * @param policies lista de validadores de policies que se aplicarán en la validación (<code>null</code> si no hay policies a aplicar).
	 * @return ValidationResult Este objeto indica si la firma es válida o no, y en este último caso
	 * indica la razón por la cual la firma no es válida
	 * @throws FirmaXMLError Si la firma no es válida
	 */
	public ResultadoValidacion validar(File firmaParaValidar, ArrayList<IValidacionPolicy> policies) throws FirmaXMLError
	{
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(firmaParaValidar);
		} catch (FileNotFoundException e) {
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR58));
			return null;
		} 
		
		FirmaXMLError excepcion = null;
		ResultadoValidacion rs = null;
		try {
			rs = validar(fis, firmaParaValidar.getParent(), policies);
		} catch (FirmaXMLError ex) {
			excepcion = ex;
		} finally {		
			try {
				// AppPerfect: Falso positivo
				fis.close();
			} catch (Exception ex) {}
		}
		
		if (excepcion != null)
			throw excepcion;
		
		return rs;
	}

	/**
	 * @param bFirmaParaValidar
	 * @return
	 * @throws FirmaXMLError
	 */
	public ResultadoValidacion validar(byte[] bFirmaParaValidar, ArrayList<IValidacionPolicy> policies) throws FirmaXMLError
	{
		// No se ha proporcionado la ruta sobre la que esta el documento a validar. Se toma por defecto XXXX
		log.debug(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_INFO2) + ESPACIO  
				+ System.getProperty(USER_DIR));
		return validar(bFirmaParaValidar, System.getProperty(USER_DIR), policies);
	}

	public ResultadoValidacion validar(byte[] bFirmaParaValidar, String path, ArrayList<IValidacionPolicy> policies) throws FirmaXMLError
	{
		ByteArrayInputStream bis = null;

		bis = new ByteArrayInputStream(bFirmaParaValidar);

		return validar(bis, path, policies);
	} 

	/**
	 * Valida la firma XML
	 * @param firmaParaValidar firchero con la firma XADES para validar
	 * @param path ruta donde se encuentran los ficheros de complemento de información (para XADES-C)
	 * @param policies lista de validadores de policies que se han de aplicar en la validación
	 * @return ValidationResult Este objeto indica si la firma es válida o no, y en este último caso
	 * indica la razón por la cual la firma no es válida
	 * @throws FirmaXMLError Si la firma no es válida
	 */
	public ResultadoValidacion validar(InputStream inputFirmaParaValidar, String path, ArrayList<IValidacionPolicy> policies) throws FirmaXMLError
	{
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true) ;

		DocumentBuilder db = null;
		try {
			db = dbf.newDocumentBuilder();
		} catch (ParserConfigurationException e1) {
			mostrarErrorValidacion(e1);
		}

		InputSource isour = null;
		try {
			isour = new InputSource(inputFirmaParaValidar);
			doc = db.parse(isour);
		} catch (FileNotFoundException e1) {
			mostrarErrorValidacion(e1);
		} catch (SAXException e1) {
			mostrarErrorValidacion(e1);
		} catch (IOException e1) {
			mostrarErrorValidacion(e1);
		}
		
		return validar(doc, path, policies);
	}
	
	public ResultadoValidacion validar(Document doc, String path, ArrayList<IValidacionPolicy> policies) throws FirmaXMLError
	{
		ArrayList<ResultadoValidacion> resultados = new ArrayList<ResultadoValidacion>();
		
		Security.addProvider(new BouncyCastleProvider());

		//Establece el idioma según la configuración
		String locale = configuracion.getValor(LOCALE);
		// Configura el idioma
		I18n.setLocale(locale, locale.toUpperCase());

		// Se recupera la lista de esquemas que se pueden validar
		// Se recomienda mantener el orden de esquemas de superior a inferior, ya que los primeros son más completos
		final String cadenaDeUrisXadesNS = configuracion.getValor(LIBRERIAXADES_VALIDARXADES);

		StringTokenizer uriXadesNS = new StringTokenizer(cadenaDeUrisXadesNS, COMA);
		boolean valor = uriXadesNS.hasMoreTokens();
		while(valor)
		{
			esquema = uriXadesNS.nextToken();
			esquemasParaValidar.add(esquema);
			valor = uriXadesNS.hasMoreTokens();
		}

		if (esquemasParaValidar.isEmpty())
		{
			// No se han encontrado esquemas para validar en el fichero de propiedades
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR1));
			throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR1));
		}

		// Validamos que el fichero de firma sea un XML bien formado

		Init.init() ;

		// Se recupera el nodo de firma Signature
		NodeList listaFirmas = doc.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_SIGNATURE);
		if (listaFirmas.getLength() == 0)
		{
			// Error en la validación. No se pudo encontrar el nodo de firma
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR2));
			throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR2));
		}

		// Si el documento tiene múltiples firmas existe más de un nodo de firma
		log.debug(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_INFO1) + ESPACIO +  listaFirmas.getLength()); // Nº Firmas presentes
		
		// Cada firma se valida como una firma única 
		int longitud = listaFirmas.getLength();
		for(int i=0; i<longitud; i++)
		{
			resultados.add(validaFirma(listaFirmas.item(i), path, policies));			
		}

		configuracion = null;
		firmaAValidar = null;
		doc = null;

		return resultados.get(0);
	}

	private ResultadoValidacion validaFirma(Node firma, String path, ArrayList<IValidacionPolicy> policies) throws FirmaXMLError  {
		// pasa las políticas indicadas al array de resultados de las políticas
		if ((policies != null) && (policies.size() > 0)) {
			Iterator<IValidacionPolicy> it = policies.iterator();
			while (it.hasNext()) {
				IValidacionPolicy valPol = it.next();
				if (valPol != null) {
					PolicyResult pr = new PolicyResult();
					pr.setPolicyVal(valPol);
					politicas.add(pr);
				}
			}
		}
		
		resultado = new ResultadoValidacion();
		X509Certificate cert = null;
		XMLSignature firmaDocumento = null;
		String uriDS = null;

		try {
			firmaDocumento = new XMLSignature((Element)firma,CADENA_VACIA);
			uriDS = firmaDocumento.getBaseNamespace();
		} catch (XMLSignatureException e) {
			// Error en la validación. Se produjo un error
			log.error(e.getMessage(), e);
			throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR7) + 
					DOS_PUNTOS_ESPACIO + e.getMessage());		
		} catch (XMLSecurityException e) {
			log.error(e.getMessage(), e);
			throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR7) + 
					DOS_PUNTOS_ESPACIO + e.getMessage());				
		}
		
		// Si existe el nodo KeyInfo, obtenemos el certificado firmante
		KeyInfo ki = firmaDocumento.getKeyInfo();
		if (ki != null) {
			try {
				cert = ki.getX509Certificate();
			} catch (KeyResolverException ex) {
				// Error en la validación. No se pudo obtener el certificado firmante
				log.error(ex.getMessage());
				throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR3));
			}
			if (cert != null)
			{
				try {
					esValido = firmaDocumento.checkSignatureValue(cert);
				} catch (XMLSignatureException ex) {
					log.info(ex.getMessage(), ex);
					// Error en la validación. La firma no tiene un formato correcto
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR4));
				}
			}
			else {
				// Error en la validación. No se ha encontrado el certificado
				log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR5));
				throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR5));
			}
		}
		else {
			// Error en la validación. KeyInfo del certificado no encontrado
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR6));
			throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR6));
		}
		
		// Se instancia la estructura que almacena los datos de la firma
		datosFirma = new DatosFirma();
		resultado.setDatosFirma(datosFirma);

		// Se almacena el certificado de firma en la cadena de certificados hasta que toda la cadena sea generada (ver validarXadesBes y C)
		cadenaCertificados.add(cert);
		datosFirma.setCadenaFirma(UtilidadCertificados.convertCertPath(cadenaCertificados));
		
		// Se obtiene el nodo raíz de la firma si la firma es válida
		firmaAValidar = (Element)firma;

		// Se obtiene el esquema
		EstructuraFirma estructuraFirma = obtenerEsquema(firmaAValidar); // En este punto se obtiene el esquema de la firma
		if (estructuraFirma == null) {
			// No se han encontrado esquemas para validar en el fichero de propiedades
			log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR1));
			throw new FirmaXMLError(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR1));
		} else {
			esquema = estructuraFirma.esquema;
			datosFirma.setEsquema(XAdESSchemas.getXAdESSchema(esquema));
		}
		
		// Una vez que sabemos que la firma es una firma XADES bien formada verificamos de qué tipo
		// específico de firma se trata: XADES-BES, XAdES-EPES, XADES-T, XAdES-C, XAdES-X, XADES-XL o XAdES-A
		try {
			tipoDocFirma = tipoFirma(firmaAValidar, esquema);
			datosFirma.setTipoFirma(tipoDocFirma);
		} catch (BadFormedSignatureException e) {
			log.error(e.getMessage());
			resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR4));
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.INVALID);
			esValido = false;
			tipoDocFirma = new DatosTipoFirma(EnumFormatoFirma.XMLSignature, false, false);
		}
		
		if (esValido && datosFirma.getTipoFirma().esXAdES_A()) {
			// No se soporta el formato de firma XAdES A
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR156));
			esValido = false;
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.UNKNOWN);
		}
		// Si es una firma XADES-BES válida continúa con el proceso de validación
		if (esValido)
		{
			if (validarXadesBes(path, estructuraFirma)) 
			{
				if (datosFirma.getTipoFirma().esXAdES_EPES()) { // El documento es una firma XADES-EPES válida. Validación incompleta
					log.info(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO5));
					resultado.setNivelValido(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO5));
				} else { // El documento es una firma XADES-BES válida. Validación incompleta
					log.info(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO1));
					resultado.setNivelValido(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO1));
				}
				resultado.setEnumNivel(EnumFormatoFirma.XAdES_BES);
				// La validación no se puede completar con la información contenida en el fichero de firma
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO6));

				// Almacenamos la fecha de Firma
				datosFirma.setFechaFirma(obtenerFechaFirma());
				
				// Almacenamos los roles de la firma
				datosFirma.setRoles(obtenerRoles(estructuraFirma));

				// Validación para XADES-T. Realiza la validación tanto si la firma es XADES-T como XADES-XL
				if((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_BES) > 0)
				{
					// Valida el sello de tiempo de la firma XADES-T
					if(validarSelloTiempoXadesT())
					{
						// El documento es una firma XADES-T válida. Validación incompleta
						log.info(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO2));
						resultado.setNivelValido(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO2));
						resultado.setEnumNivel(EnumFormatoFirma.XAdES_T);
						datosFirma.setDatosSelloTiempo(arrayDatosSello);

						// Valida los campos CompleteCertificateRefs y CompleteRevocationRefs de la firma XADES-C
						if ((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_T) > 0) {

							// Se valida XADES-C
							// AppPerfect: Falso positivo
							if (validarXadesC(path, uriDS, cert)) {
								log.info(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO4));
								resultado.setNivelValido(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO4));
								resultado.setEnumNivel(EnumFormatoFirma.XAdES_C);
								resultado.setLog(CADENA_VACIA); // Se borra el mensaje de validación incompleta
								datosFirma.setDatosOCSP(arrayDatosOCSP);
								datosFirma.setDatosCRL(arrayDatosCRL);

								// Validación para XADES-XL. Solo se realiza si la firma es XADES-XL
								if((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_X) >= 0)
								{
									// La firma XADES-XL está formado por otros formatos de firma XADES intermedios:
									// XADES-X y XADES-C que es necesario validar antes de validar XADES-XL

									// Validamos el sello de tiempo de XADES-X (La firma XAdES_XL quedó validada al validar XAdES-C)
									// AppPerfect: Falso positivo
									if (validarSelloTiempoXadesXTipo1() || validarSelloTiempoXadesXTipo2())
									{
										// La firma es una XAdES-X/XL válida
										resultado.setEnumNivel(tipoDocFirma.getTipoXAdES());
										if (EnumFormatoFirma.XAdES_X.compareTo(tipoDocFirma.getTipoXAdES()) == 0) {
											// El documento es una firma XAdES-X válida
											resultado.setNivelValido(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO7));
											log.info(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO7));
										} else {
											// El documento es una firma XAdES-XL válida
											resultado.setNivelValido(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO3));
											log.info(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO3));
										}
										datosFirma.setDatosSelloTiempo(arrayDatosSello);
										datosFirma.setDatosOCSP(arrayDatosOCSP);
									} else {
										// No se encuentra el segundo sello de tiempo correspondiente al nivel XAdES-X
										log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR103));
										resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR104));
										esValido = false;
									}
								}
							} 
						}
					}
					else
					{
						// Si el sello de tiempo de la firma XADES-T no es válido, se modifica la respuesta ya se que
						// que la firma XADES-T está incluida dentro de una firma XADES-XL o no. En el primer caso se
						// debe distinguir el primer sello de tiempo perteneciente a XADES-T del segundo sello de
						// tiempo perteneciente a XADES-X
						String sello = CADENA_VACIA;
						if ((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_XL)==0)
							sello = LIBRERIAXADES_PRIMER;

						// El valor del sello de tiempo de la firma no es válido
						log.info(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR8) +	ESPACIO +
								sello + ESPACIO +
								I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ESPACIO +
								(tipoDocFirma.getTipoXAdES())  + ESPACIO +
								I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR10));
						// Se escribe el log de sello de tiempo inválido si el Log contiene el mensaje por defecto (para no sobreescribirlo)
						if (I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_TEXTO6).equals(resultado.getLog())) {
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR8) +	ESPACIO +
									sello + ESPACIO +
									I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ESPACIO +
									(tipoDocFirma.getTipoXAdES())  + ESPACIO +
									I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR10));
						}
						esValido = false;
					}
				}
			}
			resultado.setValidate(esValido);
			resultado.setResultado(esValido?ResultadoEnum.VALID:ResultadoEnum.INVALID);
			
			// Validación del Nodo Policy del nivel EPES, si existe
			if (esValido) {
				buscaXadesEpes();
			}
		} 
		
		resultado.setDoc(doc);
		// Valida las policies indicadas
		if (esValido && (politicas.size() > 0)) {
			Iterator<PolicyResult> it = politicas.iterator();
			while (it.hasNext()) {
				PolicyResult pr = it.next();
				if (pr.getPolicyVal() == null) {
					// Política desconocida
					pr.setPolicyResult(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR105));
				} else {
					try {
						IValidacionPolicy valPol = pr.getPolicyVal();
						pr.setPolicyId(valPol.getIdentidadPolicy());
						valPol.validaPolicy((Element)firma, resultado);
					} catch (PolicyException ex) {
						log.error(ex.getMessage(), ex);
						resultado.setValidate(false);
						resultado.setResultado(ResultadoEnum.INVALID);
						resultado.setLog(ex.getMessage());
						pr.setPolicyResult(ex.getMessage());
						break;
					} catch (Throwable th) {
						// Error validando la política: XXXX
						log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR106) + 
								DOS_PUNTOS_ESPACIO + th.getMessage(), th);
						resultado.setValidate(false);
						resultado.setResultado(ResultadoEnum.INVALID);
						// Error al validar una policy. Validez de la firma desconocida
						resultado.setLog(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR71));
						pr.setPolicyResult(th.getMessage());
						break;
					}
				}
			}
		}
		
		if (politicas.size() > 0)
			datosFirma.setPoliticas(politicas);

		return resultado;
	}

	/**
	 * Busca si la firma tiene indicada alguna política y la añade al listado de políticas a validar.
	 * 
	 * @param policies listas de políticas a validar
	 * @return
	 */
	private void buscaXadesEpes() {
		// Se valida la politica de firmas si existe el nodo
		NodeList signaturePolicyList = firmaAValidar.getElementsByTagNameNS(esquema, ConstantesXADES.LIBRERIAXADES_POLICY_SIGNATUREPOLICYIDENTIFIER);

		if (signaturePolicyList.getLength() == 1) {
			// Se recoge el nodo SignaturePolicyIdentifier
			Element signaturePolicyIdentifierNode = (Element) signaturePolicyList.item(0);
			SignaturePolicyIdentifier spi;
			try {
				spi = new SignaturePolicyIdentifier(XAdESSchemas.getXAdESSchema(esquema));
				if (!spi.isThisNode(signaturePolicyIdentifierNode))
					throw new InvalidInfoNodeException(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR107));
				spi.load((signaturePolicyIdentifierNode));
			} catch (InvalidInfoNodeException ex) {
				// El nodo encontrado no es un SignaturePolicyIdentifier válido
				log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR108));
				// Información de política mal formada
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR109));
				esValido = false;
				resultado.setValidate(false);
				resultado.setResultado(ResultadoEnum.INVALID);
				return;
			}

			String clave = ConstantesXADES.LIBRERIAXADES_IMPLIEDPOLICY_MANAGER;
			if (!spi.isImplied())
				clave = Utilidades.binary2String(Base64Coder.decode(spi.getSignaturePolicyId().getSigPolicyHash().getValue().getValue()));
			
			// Se busca el validador asociado
			PoliciesManager policiesManager = PoliciesManager.getInstance();
			IValidacionPolicy valPol = policiesManager.getValidadorPolicy(clave);
			if (valPol == null) {
				PolicyResult pr = new PolicyResult();
				if (spi.isImplied())
					pr.setPolicyId(ConstantesXADES.LIBRERIAXADES_IMPLIEDPOLICY_MANAGER);
				else {
					String polId =  spi.getSignaturePolicyId().getSigPolicyId().getIdentifier().getUri().toString();
					try {
						polId = URLDecoder.decode(polId, UTF8);
					} catch (UnsupportedEncodingException ex) {}
					// La firma contiene políticas desconocidas
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR102));
					pr.setPolicyId(polId);
				}
				politicas.add(pr);
			} else if (!politicas.contains(valPol)) {
				PolicyResult pr = new PolicyResult();
				pr.setPolicyVal(valPol);
				politicas.add(pr);
			}
		}
		else if (signaturePolicyList.getLength() > 1) {
			// Demasiadas políticas en un nodo de firma
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR110));
			// Modelo de políticas no soportado
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR111));
			esValido = false;
			resultado.setValidate(false);
			resultado.setResultado(ResultadoEnum.INVALID);
			return;
		}
	}

	private void mostrarErrorValidacion(Exception ex) throws FirmaXMLError{
		// El documento de firma no es un documento XML bien formado
		log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR28), ex);
		throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR28));
	}
	
	/**
	 * Valida XAdES-BES.
	 * @return true Si la fecha de firma es anterior a la actual, si el certificado firmante es el que
	 *              aparece en el nodo SigningCertificate y si existe al menos un nodo Reference con una URI apuntando al nodo SignedProperties.
	 *              y dicho nodo contiene un attributo de tipo Type con un valor dependiente del esquema
	 */
	private boolean validarXadesBes(String path, EstructuraFirma estructuraFirma) {
		
		if (estructuraFirma.firma == null) {
			esValido = false;
			// No se encuentra la firma a validar
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR76));
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR76));
			return false;
		}
		
		// Se valida, si existe, que SigningTime no sea posterior a la fecha actual		
		Date fechaFirma = obtenerFechaFirma();
		if (fechaFirma != null) {
			if (fechaFirma.after(new Date(System.currentTimeMillis()))) {
				esValido = false;
				// Firma inv\u00e1lida. La fecha del sello de tiempo del nivel XAdES BES es posterior a la actual
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR157));
				log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR157));
				return false;
			}
		}
		
		// Se obtiene la cadena de certificados contenida en SigningCertificate si existe
		ArrayList<DatosX509> certificadosSigning = new ArrayList<DatosX509> ();
		DatosX509 datos = new DatosX509();
		ArrayList<Element> nodosSigningCertificate = UtilidadTratarNodo.obtenerNodos(estructuraFirma.signedSignatureProperties, null, new NombreNodo(estructuraFirma.esquema, LIBRERIAXADES_SIGNINGCERTIFICATE));
//		NodeList nodosSigningCertificate = firmaAValidar.getElementsByTagNameNS(esquema, LIBRERIAXADES_SIGNINGCERTIFICATE);
		if (nodosSigningCertificate.size() > 0) {
			Node nodoSigningCertificate = nodosSigningCertificate.get(0);
			NodeList nodosCert = nodoSigningCertificate.getChildNodes();
			int nodosCertSize = nodosCert.getLength();
			for(int i = 0; i < nodosCertSize; ++i) {
				Node nodoCert = nodosCert.item(i);
				Element certDigest = (Element)((Element)nodoCert).getElementsByTagNameNS(esquema, LIBRERIAXADES_CERTDIGEST).item(0);
				if (certDigest != null) {
					NodeList digAlgs = certDigest.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_DIGEST_METHOD);
					if (digAlgs != null) {
						Element certDigestAlgElement = (Element)digAlgs.item(0);
						datos.setAlgMethod(certDigestAlgElement.getAttributes().getNamedItem(ALGORITHM).getNodeValue());
					}
					NodeList digValues = certDigest.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_DIGESTVALUE);
					if (digValues != null) {
						Element certDigestValElement = (Element)digValues.item(0);
						datos.setDigestValue(certDigestValElement.getFirstChild().getNodeValue());
					}
				}
				Element issuerSerial = (Element)((Element)nodoCert).getElementsByTagNameNS(esquema, LIBRERIAXADES_ISSUER_SERIAL).item(0);
				if (issuerSerial != null) {
					NodeList issuerVals = issuerSerial.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_X_509_ISSUER_NAME);
					if (issuerVals != null) {
						Element issuerValElement = (Element)issuerVals.item(0);
						String issuerName = issuerValElement.getFirstChild().getNodeValue();
						try {
							X500Principal prin = new X500Principal(issuerName);
							datos.setIssuer(prin.getName());
						} catch (IllegalArgumentException ex) {
							esValido = false;
							// Error en la validación. No se pudo obtener el certificado firmante
							resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_3));
							// Error al instanciar la factoría de certificados
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR23), ex);
							return false;
						} catch (NullPointerException ex) {
							esValido = false;
							// Error en la validación. No se pudo obtener el certificado firmante
							resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_3));
							// Error al instanciar la factoría de certificados
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR23), ex);
							return false;
						}
					}
					NodeList serialVals = issuerSerial.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_X_509_SERIAL_NUMBER);
					if (serialVals != null) {
						Element serialValElement = (Element)serialVals.item(0);
						datos.setSerial(new BigInteger(serialValElement.getFirstChild().getNodeValue()));
					}
				}
				certificadosSigning.add(datos);
			}
		} 

		if (certificadosSigning.size() > 0) { // Si no existe éste nodo, no es preciso validarlo

			// Se obtiene la cadena de certificados de KeyInfo, si existe
			ArrayList<X509Certificate> certificadosKeyInfo = new ArrayList<X509Certificate> ();
			NodeList nodosKeyInfo = firmaAValidar.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_KEY_INFO);
			if (nodosKeyInfo.getLength() > 0) {
				Element nodoKeyInfo = (Element)nodosKeyInfo.item(0);
				// Obtenemos los nodos X509Data
				NodeList nodosX509Data = nodoKeyInfo.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_X509_DATA);
				int nodosX509DataLenght = nodosX509Data.getLength();
				for(int i = 0; i < nodosX509DataLenght; ++i) {
					Element nodoX509Data = (Element)nodosX509Data.item(i);
					// Obtenemos sus nodos X509Certificate
					NodeList x509Cert = nodoX509Data.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_X509_CERTIFICATE);
					int x509CertLenght = x509Cert.getLength();
					for(int x = 0; x < x509CertLenght; ++x) {
						Node nodoX509Certificate = x509Cert.item(x);
						try
						{
							ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(nodoX509Certificate.getFirstChild().getNodeValue()));
							CertificateFactory cf = CertificateFactory.getInstance(X_509);
							certificadosKeyInfo.add((X509Certificate)cf.generateCertificate(bais));
						} catch (CertificateException e1) {
							esValido = false;
							// Error en la validación. No se pudo obtener el certificado firmante
							resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_3));
							// Error al instanciar la factoría de certificados
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR23), e1);
							return false;
						} 
					}
				}
			}

			// Se obtiene la cadena de certificados de CertificateValues o en su lugar, CompleteCertificateRefs
			ArrayList<X509Certificate> certificadosRef = new ArrayList<X509Certificate> ();
			NodeList nodosCertValue = firmaAValidar.getElementsByTagNameNS(esquema, CERTIFICATE_VALUES);
			if (nodosCertValue.getLength() > 0) {
				Element nodoCertValue = (Element)nodosCertValue.item(0);
				// Obtenemos los nodos EncapsulatedX509Certificate
				NodeList nodosX509Cert = nodoCertValue.getElementsByTagNameNS(esquema, LIBRERIAXADES_X509VALUE);
				int nodosX509DataLenght = nodosX509Cert.getLength();
				for(int i = 0; i < nodosX509DataLenght; ++i) {
					Element nodoX509Cert = (Element)nodosX509Cert.item(i);			
					try
					{
						ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(nodoX509Cert.getFirstChild().getNodeValue()));
						CertificateFactory cf = CertificateFactory.getInstance(X_509);
						certificadosRef.add((X509Certificate)cf.generateCertificate(bais));
					} catch (CertificateException e1) {
						esValido = false;
						// Firma inválida. No se pudo obtener el certificado de firma
						resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_3));
						// Error al instanciar la factoría de certificados
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR23), e1);
						return false;
					} 		
				}
			} else 
			{
				// Se obtienen los nodos CompleteCertificateRefs
				NodeList nodosCompCertRef = firmaAValidar.getElementsByTagNameNS(esquema, COMPLETE_CERTIFICATE_REFS);
				if (nodosCompCertRef.getLength() > 0) {
					// Obtenemos el nodo CertRefs, que contiene los nodos Cert
					Node nodoCertRefs = nodosCompCertRef.item(0).getFirstChild();
					NodeList nodosCert = nodoCertRefs.getChildNodes();
					int nodosCertSize = nodosCert.getLength();
					for(int i = 0; i < nodosCertSize; ++i) {
						Node nodoCert = nodosCert.item(i);
						String uri = null;
						try {
							uri = URLDecoder.decode(nodoCert.getAttributes().getNamedItem(URI).getNodeValue(), UTF8);
						} catch (UnsupportedEncodingException e) {
							// No se puede decodificar la URI a UTF-8 del nodo CertRef para la validación
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR31), e);
							esValido = false;
							// Firma inválida. No se pudo obtener el certificado firmante
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR3));
						} catch (Exception e) {
							// No se pudo recuperar la URI del nodo CertDigest
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR65), e);
							esValido = false;
							// Firma inválida. No se pudo obtener el certificado firmante
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR3));
						}
						// La uri puede apuntar a un nodo dentro de CertificateValues o a un fichero externo.
						// Dado que el flujo impone que no exista dicho nodo, se va a buscar el fichero externo 
						if (uri != null) {
							// Se recoge el destino
							if (path != null && !path.endsWith(System.getProperty(FILE_SEPARATOR)))
								path = path + System.getProperty(FILE_SEPARATOR);
							
							File certPath = new File(path + uri);
							X509Certificate certFile = null;
							try {
								FileInputStream fis = new FileInputStream(certPath);
								try
								{
									// Se obtiene el certificado en su formato del archivo de la URI
									CertificateFactory cf = CertificateFactory.getInstance(X_509);
									certFile = (X509Certificate)cf.generateCertificate(fis);
								} catch (CertificateException e1) {
									// Error al instanciar la factoría de certificados
									log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR23), e1);
									esValido = false;
									// Firma inválida. No se pudo obtener el certificado firmante
									resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR3));
									return false;
								} finally {
									if (fis != null) {
										try {
											// AppPerfect: Falso positivo
											fis.close();
										} catch (IOException e) {}
									}
								}
							} catch (FileNotFoundException e) {
								// No se pueden encontrar los archivos de certificado para la validación
								log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR50), e);
								esValido = false;
								// Firma inválida. No se pudo obtener el certificado firmante
								resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR3));
								return false;
							}

							// Se toman las variables de la firma para validar que sean correctas
							
							Element certElement = (Element)nodoCert;		
							Element certDigest = (Element)certElement.getElementsByTagNameNS(esquema, LIBRERIAXADES_CERTDIGEST).item(0);	// Sacamos CertDigest

							String alg = null;     			
							String digest = null;
							String resumenCertificado = CADENA_VACIA;
							if (certDigest != null) {
								Node algorithm = certDigest.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_DIGEST_METHOD).item(0);				// Sacamos DigestAlgorithm
								Node value = certDigest.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_DIGESTVALUE).item(0);					// Sacamos DigestValue

								alg = algorithm.getAttributes().getNamedItem(ALGORITHM).getNodeValue(); 	// Guardamos el valor del algoritmo        			
								digest = value.getFirstChild().getNodeValue(); 								// Guardamos valor del digest

								// Se comprueba que el valor digest del nodo coincida con el digest de la uri
								try
								{
									MessageDigest haseador = UtilidadFirmaElectronica.getMessageDigest(alg);
									if (haseador == null) {
										esValido = false;
										// No se encontró el algoritmo para calcular el valor del digest del certificado
										resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_16));
										// No se puede calcular la huella del certificado para la validación
										log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR52));
										return false;
									}
									byte[] resumenMensajeByte = haseador.digest(certFile.getEncoded());
									resumenCertificado = new String(Base64Coder.encode(resumenMensajeByte));
								} catch (CertificateEncodingException e) {
									// No se puede calcular el digest del certificado para la validación: XXXX
									log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR52) + 
											DOS_PUNTOS_ESPACIO + e.getMessage(), e);				
									esValido = false;
									resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR52));
									return false;
								}
								
								if (digest.equals(resumenCertificado)) {
									certificadosRef.add(certFile);
								} else {
									esValido = false;
									// No coincide el certificado con el almacenado
									resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR53));
									log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR53));
									return false;
								}
								
							} else {
								// No se pueden recuperar los nodos de CompleteCertificateRefs
								log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR66));
								resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR66));
								esValido = false;
								return false;
							}
						
						} else {
							// No se puede continuar la validación dado que hay CertificateRefs sin URI, ni certificateValues
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR83));				
							esValido = false;
							// Firma inválida. No se pudo obtener el certificado firmante
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR3));
							return false;
						}
					}
				} 
			}

			// Con ambos resultados (certificadosKeyInfo y certificadosRef) construir una cadena
			certificadosRef.addAll(certificadosKeyInfo);
			ArrayList<ArrayList<X509Certificate>> certChains = UtilidadCertificados.getCertPathsArray(certificadosRef);
			if (certChains.size() > 1) {
				// No se pueden validar dos o más cadenas de certificados
				esValido = false;
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR84));
				log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR84));
				return false;
			} else {
				cadenaCertificados = certChains.get(0);
				// Almacenamos la cadena construida
				datosFirma.setCadenaFirma(UtilidadCertificados.convertCertPath(cadenaCertificados));
			}

			// Se compara el certificado firmante (1º en KeyInfo) contra todos los signingCertificate
			X509Certificate certFirmante = certificadosKeyInfo.get(0);
			String certFirmIssuer = certFirmante.getIssuerX500Principal().getName();
			BigInteger certFirmSerial = certFirmante.getSerialNumber();

			boolean coincidencia = false;
			for (int i = 0; i < certificadosSigning.size(); ++i) {
				DatosX509 certAComparar = certificadosSigning.get(i);
				if (certFirmIssuer.equals(certAComparar.getIssuer()) &&
						certFirmSerial.equals(certAComparar.getSerial())) {
					// En caso de que haya alguno coincidente, se busca 1ºKeyInfo/1ºX509Data/X509IssuerSerial
					if (nodosKeyInfo.getLength() > 0) {
						Element nodoKeyInfo = (Element)nodosKeyInfo.item(0); // Tomamos el primer nodo KeyInfo
						Element primerNodoX509Data = (Element)nodoKeyInfo.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_X509_DATA).item(0);
						NodeList nodosIssuerSerial = primerNodoX509Data.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_X509_SERIAL_ISSUER);
						if (nodosIssuerSerial.getLength() > 0) {
							// y si existe, se comprueba que el valor de ese nodo sea el mismo que el indicado en 
							// el nodo de información "certAComparar"
							String issuer = null;
							BigInteger serial = null;
							Element nodoIssuerSerial = (Element)nodosIssuerSerial.item(0);
							NodeList issuerVals = nodoIssuerSerial.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_X_509_ISSUER_NAME);
							if (issuerVals != null) {
								Element issuerValElement = (Element)issuerVals.item(0);
								issuer = issuerValElement.getFirstChild().getNodeValue();
							}
							NodeList serialVals = nodoIssuerSerial.getElementsByTagNameNS(SCHEMA_DSIG, LIBRERIAXADES_X_509_SERIAL_NUMBER);
							if (serialVals != null) {
								Element serialValElement = (Element)serialVals.item(0);
								serial = new BigInteger(serialValElement.getFirstChild().getNodeValue());
							}
							
							if ((certAComparar.getIssuer()).equals(issuer) &&
									(certAComparar.getSerial()).equals(serial)) {
								// El nodo IssuerSerial es válido
							} else {
								// No coincide la información del nodo X509IssuerSerial con el certificado de firma
								esValido = false;
								resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR85));
								log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR85));
								return false;
							}
						}
					}
					// Se comprueba que el digest de certFirmante sea igual al encontrado con mismo issuer y serial
					// Cálculo del digest del certificado de firma
					MessageDigest haseador = UtilidadFirmaElectronica.getMessageDigest(certAComparar.getAlgMethod());
					byte[] digestCertFirmante = null;
					try {
						digestCertFirmante = haseador.digest(certFirmante.getEncoded());
					} catch (CertificateEncodingException e) {
						// No se puede codificar el certificado firmante para calcular su digest
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR52));
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR52));
						return false;
					}
					if (Utilidades.isEqual(digestCertFirmante, Base64Coder.decode(certAComparar.getDigestValue()))) {
						// El certificado de firma se corresponde con el nodo SigningCertificate, por lo que es válido
						coincidencia = true;
						// Se elimina el coincidente para la siguiente validación
						certificadosSigning.remove(i);
						break;
					} else {
						// No coinciden los valores de digest del nodo de firma con los de la cadena generada
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR86));
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR86));
						return false;
					}
				}	
			}

			// Si no se encontró ninguna coincidencia con el certificado firmante se da la firma por inválida
			if (!coincidencia) {
				// Incorrectamente identificado el certificado de firma
				esValido = false;
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR87));
				log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR87));
				return false;
			}

			// Se comprueba que en el resto de SigningCertificate, tenga coincidencia con alguno dentro de las cadenas generadas
			int validos = 0;
			for (int i = 0; i < certificadosSigning.size(); ++i) {
				DatosX509 certAComparar = certificadosSigning.get(i);
				for (int x = 0; x < cadenaCertificados.size(); ++x) {
					X509Certificate certContenidos = (X509Certificate)cadenaCertificados.get(x);
					String certContIssuer = certContenidos.getIssuerX500Principal().getName();
					BigInteger certContSerial = certContenidos.getSerialNumber();

					if (certContIssuer.equals(certAComparar.getIssuer()) &&
							certContSerial.equals(certAComparar.getSerial())) {
						// Cálculo del digest del certificado de firma
						MessageDigest haseador = UtilidadFirmaElectronica.getMessageDigest(certAComparar.getAlgMethod());
						byte[] digestCertContenidos = null;
						try {
							digestCertContenidos = haseador.digest(certContenidos.getEncoded());
						} catch (CertificateEncodingException e) {
							// No se puede codificar el certificado contenido en KeyInfo para calcular su digest
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR52));
							log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8), e);
							return false;
						}
						if (Utilidades.isEqual(digestCertContenidos, Base64Coder.decode(certAComparar.getDigestValue()))) {
							// Certificado válido
							validos++;
							continue;
						} else {
							// No coinciden los valores de digest de los nodos SigningCertificate con los de la cadena de firma
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR88));
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR88));
							return false;
						}
					} 
				}
			}
			
			if (validos < certificadosSigning.size()) {
				// Hay certificados dentro del nodo SigningCertificate sin coincidencia con los certificados de referencia
				esValido = false;
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR89));
				log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR89));
				return false;
			}
		}
		
		// Se valida que exista un Reference con la URI apuntando al Id de SignedProperties (dependiente del esquema)
		NodeList nodosSignedProperties = firmaAValidar.getElementsByTagNameNS(esquema, SIGNED_PROPERTIES);
		
		if (nodosSignedProperties.getLength() == 0) {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR77));
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR77));
			return false;
		}
			
		Element nodoSignedProperties = (Element)nodosSignedProperties.item(0);
		Node signedPropertiesId = nodoSignedProperties.getAttributes().getNamedItem(ID);
		if (signedPropertiesId == null) {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR78));
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR78));
			return false;
		}
		
		String nodoId = signedPropertiesId.getNodeValue();
		
		NodeList references = firmaAValidar.getElementsByTagNameNS(SCHEMA_DSIG, REFERENCE);
		int referencesLenght = references.getLength();
		
		if (referencesLenght == 0) {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR79));
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR79));
			return false;
		}
		
		String tipoEsperado = UtilidadFirmaElectronica.obtenerTipoReference(esquema);
		
		for (int i = 0; i < referencesLenght; i++) {
			Element reference = (Element)references.item(i);
			String uri = reference.getAttribute(URI);
			if (uri == null)
				continue;

			if (uri.startsWith(ALMOHADILLA))
				uri = uri.substring(1);
			else
				continue;
			
			if (nodoId.equals(uri)) {
				Node referenceType = reference.getAttributes().getNamedItem(TYPE);
				if (referenceType == null)
					continue;
				if ((tipoEsperado).equals(referenceType.getNodeValue()))				
					return true;
			}
		}
		
		// Si se alcanza éste punto es porque no se encontró ninguna coincidencia
		esValido = false;
		resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR80));
		log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR80));
		
		return false;
	}
	
	/**
	 * Valida el sello de tiempo correspondiente a la firma XADES-T
	 * @return Falso si el sello no está bien formado o si la firma no se corresponde con el elemento
	 * de firma del documento
	 */
	private boolean validarSelloTiempoXadesT()
	{
		TSCliente clienteTSA = null;
		NodeList nodosSignatureTimeStamp = null;
		NodeList nodesEncapsulatedTimeStamp = null;
		Element encapsulatedTimeStampElement = null;
		String encapsulatedTS = null;
		byte[] timeStampBytes = null ;
		TSValidacion tsv1 = null;
		DatosSelloTiempo datosSelloTiempo = new DatosSelloTiempo();
		String servidorProxy = configuracion.getValor(LIBRERIAXADES_PROXYURL);
		String puertoProxy = configuracion.getValor(LIBRERIAXADES_PROXYPORT);
		String proxyUser = configuracion.getValor(LIBRERIAXADES_PROXYUSER);
		String proxyPass = configuracion.getValor(LIBRERIAXADES_PROXYPASS);
		int numeroPuertoProxy = 8080;
		try {
			numeroPuertoProxy = Integer.parseInt(puertoProxy);
		} catch (Exception e) {
			log.warn(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_WARN1));
		}

		try
		{
			if (configuracion.comparar(LIBRERIAXADES_ISPROXY)) {
				System.setProperty("http.proxyHost", servidorProxy);
				System.setProperty("http.proxyPort", Integer.toString(numeroPuertoProxy));
				if (configuracion.comparar(LIBRERIAXADES_ISPROXYAUTH)) {
					Authenticator.setDefault(new SimpleAuthenticator(proxyUser, proxyPass));
				} 
				else {
					Authenticator.setDefault(null);
				}
			}
			clienteTSA = new TSCliente(CADENA_VACIA,LIBRERIAXADES_SHA1);

			nodosSignatureTimeStamp = firmaAValidar.getElementsByTagNameNS(esquema, LIBRERIAXADES_SIGNATURETIMESTAMP);
			if (nodosSignatureTimeStamp.getLength() <= 0) {
				// No se puede encontrar el nodo SignatureTimeStamp
				esValido = false;
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR12));
				log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_21));	
				return esValido;
			}
			
			Element nodoSigTimeStamp = (Element)nodosSignatureTimeStamp.item(0);
			if (esquema.equals(SCHEMA_XADES_122)) {
				NodeList nodosInclude = nodoSigTimeStamp.getElementsByTagNameNS(esquema, INCLUDE);
				if ( nodosInclude == null ||nodosInclude.getLength() <= 0 || nodosInclude.getLength() > 1) {
					// Número de nodos Include inesperado
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR12));
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR94) + 
							ESPACIO + nodosInclude==null?0:nodosInclude.getLength());	
					return esValido;
				}
				NamedNodeMap hashAttrb = nodosInclude.item(0).getAttributes();
				if (hashAttrb == null || 
						hashAttrb.getLength() != 1 || 
						hashAttrb.getNamedItem(URI) == null) {
					// No se puede recuperar la URI del nodo Include
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR12));
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR92));	
					return esValido;
				}
				String timeStampUri = hashAttrb.getNamedItem(URI).getNodeValue();
				Element nodoReferenciado = UtilidadTratarNodo.getElementById(firmaAValidar, timeStampUri.substring(1));
				if (nodoReferenciado == null || !SIGNATURE_VALUE.equals(nodoReferenciado.getLocalName())) {
					// No se puede recuperar el nodo SignatureValue con Id XXXX
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR12));
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR95) + 
							ESPACIO + SIGNATURE_VALUE + ESPACIO + timeStampUri);	
					return esValido;
				}
			}
			
			// Se valida, si existe, el nodo CanonicalizationMethod    
			NodeList nodosCanonicalizationMethod = nodoSigTimeStamp.getElementsByTagNameNS(SCHEMA_DSIG, CANONICALIZATION_METHOD);
			int numNodosCanonicalization = nodosCanonicalizationMethod.getLength();
			if (numNodosCanonicalization > 0) {
				Element nodoCanonicalizationMethod = (Element)nodosCanonicalizationMethod.item(0);
				String method = nodoCanonicalizationMethod.getAttribute(ALGORITHM);
				if (!URL_CANONICALIZATION.equals(method)) {
					esValido = false;
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR100) + 
							ESPACIO + method);
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR100) + 
							ESPACIO + method);
					return esValido;
				}
			}
			
			// Se chequea la validez del sello de tiempo encapsulado
			nodesEncapsulatedTimeStamp = firmaAValidar.getElementsByTagNameNS(esquema, LIBRERIAXADES_ENCTIMESTAMP);
			encapsulatedTimeStampElement = (Element)nodesEncapsulatedTimeStamp.item(0);
			encapsulatedTS = encapsulatedTimeStampElement.getFirstChild().getNodeValue() ;
			timeStampBytes = Base64.decode(encapsulatedTS) ;


			byte[] nodeSignatureValue = UtilidadTratarNodo.obtenerByteNodo(firmaAValidar, SCHEMA_DSIG, LIBRERIAXADES_SIGNATUREVALUE);
			tsv1 = clienteTSA.validarSelloTiempo(nodeSignatureValue, timeStampBytes);

			if(!tsv1.isRespuesta())
				esValido = false;
			
			Date fechaSello = tsv1.getFechaDate();
			if (fechaSello != null) {
				if (fechaSello.after(new Date(System.currentTimeMillis()))) {
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR81));
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR81));
					return false;
				}
			}
			
			if (esValido) {
				try {
					datosSelloTiempo.setTst(tsv1.getTst()); 
					datosSelloTiempo.setFecha(fechaSello);
					datosSelloTiempo.setEmisor(tsv1.getEmisor());
					datosSelloTiempo.setAlgoritmo(TSPAlgoritmos.getAlgName(tsv1.getSelloAlg()));					
					datosSelloTiempo.setPrecision(tsv1.getPrecisionLong());
					datosSelloTiempo.setTipoSello(TipoSellosTiempo.CLASE_T);
				} catch (Exception e) {
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR64));
				}
				
				arrayDatosSello.add(datosSelloTiempo);
			}
		}
		catch (NoSuchAlgorithmException e)
		{
			esValido = false;
			// Se ha producido un error al validar XADES-T
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR12));
			log.error(e.getMessage());
		}
		catch (NoSuchProviderException e)
		{
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR12));
			log.error(e.getMessage());
		}
		catch (CertStoreException e)
		{
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR12));
			log.error(e.getMessage());
		}
		catch (FirmaXMLError e)
		{
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR12));
			log.error(e.getMessage());
		}
		catch (TSPException e)
		{
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR12));
			log.error(e.getMessage());
		}
		catch (IOException e)
		{
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR12));
			log.error(e.getMessage());
		}
		catch (TSClienteError e)
		{
			String sello = CADENA_VACIA;
			if ((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_XL)==0)
				sello = LIBRERIAXADES_PRIMER;

			esValido = false;
			// El sello de tiempo no tiene un formato correcto
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR8) + ESPACIO +
					sello + I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ESPACIO +
					tipoDocFirma.getTipoXAdES() + ESPACIO +
					I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR13));
			log.error(e.getMessage());
		}
		catch (Exception e)
		{
			String sello = CADENA_VACIA;
			if ((tipoDocFirma.getTipoXAdES()).compareTo(EnumFormatoFirma.XAdES_XL)==0)
				sello = LIBRERIAXADES_PRIMER;

			esValido = false;
			// El sello de tiempo no tiene un formato correcto
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR8) + ESPACIO +
					sello + I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ESPACIO +
					tipoDocFirma + ESPACIO +
					I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR13));
			log.error(e.getMessage());
		}
		finally
		{
			clienteTSA = null;
			nodesEncapsulatedTimeStamp = null;
			encapsulatedTimeStampElement = null;
			encapsulatedTS = null;
			timeStampBytes = null;
			tsv1 = null;
		}
		
		return esValido;
	}


	/**
	 * Valida el sello de tiempo de tipo 1 implícito correspondiente a la firma XADES-X de los esquemas 1.2.2 y 1.3.2
	 * @return Falso si el sello de tiempo no está bien formado o si la firma no se corresponde con
	 * los elementos combinados del documento. Los elementos son los siguientes:
	 * 		- SignatureValue
	 * 		- SignatureTimestamp
	 * 		- CompleteCertificateRefs
	 * 		- CompleteRevocationRefs
	 * 	Opcionalmente en el esquema 1.2.2 y 1.3.2:
	 * 		- AttributeCertificateRefs
	 * 		- AttributeRevocationRefs
	 */
	private boolean validarSelloTiempoXadesXTipo1()
	{
		// Se obtiene el/los nodo/s SigAndRefsTimeStamp. Se validan todos los encontrados 
		NodeList nodesSigAndRefsTimeStamp = firmaAValidar.getElementsByTagNameNS(esquema, SIG_AND_REFS_TIME_STAMP);
		int numSigAndRefs = nodesSigAndRefsTimeStamp.getLength();

		if (numSigAndRefs == 0)
			return false;
		
		for (int i = 0; i < numSigAndRefs; ++i) {
			esValido = validarSegundoSelloTiempo((Element)nodesSigAndRefsTimeStamp.item(i));
			if (!esValido)
				break;
		}
		
		return esValido;
	}
	
	/**
	 * Valida el sello de tiempo de tipo 2 explícito correspondiente a la firma XADES-X de los esquemas 1.2.2 y 1.3.2
	 * @return Falso si el sello de tiempo no está bien formado o si la firma no se corresponde con
	 * los elementos combinados del documento. Los elementos son los siguientes:
	 * 		- CompleteCertificateRefs
	 * 		- CompleteRevocationRefs
	 * 	Opcionalmente en el esquema 1.2.2 y 1.3.2:
	 * 		- AttributeCertificateRefs
	 * 		- AttributeRevocationRefs
	 */
	private boolean validarSelloTiempoXadesXTipo2()
	{
		
		// Se obtiene el/los nodo/s RefsOnlyTimeStamp. Se validan todos los encontrados 
		NodeList nodesRefsOnlyTimeStamp = firmaAValidar.getElementsByTagNameNS(esquema, REFS_ONLY_TIME_STAMP);
		int numRefsOnly = nodesRefsOnlyTimeStamp.getLength();
		
		if (numRefsOnly == 0)
			return false;
		
		for (int i = 0; i < numRefsOnly; ++i) {
			esValido = validarSegundoSelloTiempo((Element)nodesRefsOnlyTimeStamp.item(i));
			if (!esValido)
				break;
		}
		
		return esValido;
	}
	
	/**
	 * Valida el sello de tiempo de correspondiente a la firma XADES-X de los esquemas 1.2.2 y 1.3.2
	 * @return Falso si el sello de tiempo no está bien formado o si la firma no se corresponde con
	 * los elementos combinados del documento. 
	 */
	private boolean validarSegundoSelloTiempo(Element selloTiempo)
	{

		TSValidacion tsv2 = null;
		DatosSelloTiempo datosSelloTiempo = new DatosSelloTiempo();
		TipoSellosTiempo tipoSello = TipoSellosTiempo.CLASE_X_TIPO_1;
		
		if (new NombreNodo(esquema, SIG_AND_REFS_TIME_STAMP).equals(
				new NombreNodo(selloTiempo.getNamespaceURI(), selloTiempo.getLocalName())))
			tipoSello = TipoSellosTiempo.CLASE_X_TIPO_1;
		else if (new NombreNodo(esquema, REFS_ONLY_TIME_STAMP).equals(
				new NombreNodo(selloTiempo.getNamespaceURI(), selloTiempo.getLocalName())))
			tipoSello = TipoSellosTiempo.CLASE_X_TIPO_2;	
		else {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR16));
			// El sello de tiempo xxx no es un sello válido
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR8)+ ESPACIO +
					I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR9) + ESPACIO + 
					selloTiempo.getLocalName() + ESPACIO + I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR10));
			return esValido;
		}

		// Se obtiene el listado de elementos de un sello de tiempo XAdES X
		ArrayList<Element> elementosSelloX = null;
		
		try {
			if (TipoSellosTiempo.CLASE_X_TIPO_1.equals(tipoSello))
				elementosSelloX = UtilidadXadesX.obtenerListadoXADESX1imp(esquema, firmaAValidar, selloTiempo);
			else 
				elementosSelloX = UtilidadXadesX.obtenerListadoXADESX2exp(esquema, firmaAValidar, selloTiempo);		
		} catch (BadFormedSignatureException e) {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR16));
			log.error(e.getMessage(), e);
			return esValido;
		} catch (FirmaXMLError e) {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR16));
			log.error(e.getMessage(), e);
			return esValido;
		}
		
		if (SCHEMA_XADES_122.equals(esquema)) {
			// Se obtienen las Ids de los nodos del sello de tiempo X
			ArrayList<String> elementosIdSelloX = UtilidadTratarNodo.obtenerIDs(elementosSelloX);

			// Se recogen todos los nodos Include dentro del sello de tiempo XAdES-X
			NodeList nodosInclude = selloTiempo.getElementsByTagNameNS(esquema, INCLUDE);
			int numNodosInclude = nodosInclude.getLength();

			ArrayList<String> urisInclude = new ArrayList<String>(numNodosInclude) ;
			Element nodoInclude = null;

			// Se recoge la URI de los nodos Include por orden de aparición
			for (int j = 0; j < numNodosInclude ; ++j) {			
				if (j == 0)
					nodoInclude = (Element)selloTiempo.getFirstChild();
				else
					nodoInclude = (Element)nodoInclude.getNextSibling();

				if (nodoInclude == null || !INCLUDE.equals(nodoInclude.getLocalName())) {
					// No se puede recuperar el nodo Include
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR93));
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR93));
					return esValido;
				}

				// Se obtiene la URI del nodo Include
				NamedNodeMap atributosNodo = nodoInclude.getAttributes();
				if (atributosNodo == null || atributosNodo.getNamedItem(URI) == null) {
					// No se puede recuperar la URI del nodo Include
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR92));
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR92));
					return esValido;
				}
				String uriInclude = atributosNodo.getNamedItem(URI).getNodeValue();

				urisInclude.add(uriInclude);
			}

			// Comparamos ambos listados
			for (int j = 0; j < numNodosInclude; ++j) {			
				String idUri = urisInclude.get(j).substring(1);
				if (!idUri.equals(elementosIdSelloX.get(j))) {
					// No se corresponde el orden de los nodos de referencia con el orden esperado según esquema
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR97) + 
							ESPACIO + idUri + ESPACIO +  
							I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR98));
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR97) + 
							ESPACIO + idUri + ESPACIO +  
							I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR98));	
					return esValido;
				} 
			}
		} // Fin de la validación para esquemas 1.2.2
		else if (SCHEMA_XADES_132.equals(esquema)) { // Si es esquema 1.3.2, no deben existir nodos Include			
			// Se recogen los nodos Include si existen
			NodeList nodosInclude = selloTiempo.getElementsByTagNameNS(esquema, INCLUDE);
			int numNodosInclude = nodosInclude.getLength();

			if (numNodosInclude < 0) {
				// Inválido, no se pueden validar sellos de este tipo en el esquema 1.3.2 
				esValido = false;
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR101));
				log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR101));	
				return esValido;
			}
		}

		// Se valida, si existe, el nodo CanonicalizationMethod    
		NodeList nodosCanonicalizationMethod = selloTiempo.getElementsByTagNameNS(SCHEMA_DSIG, CANONICALIZATION_METHOD);
		int numNodosCanonicalization = nodosCanonicalizationMethod.getLength();
		if (numNodosCanonicalization > 0) {
			Element nodoCanonicalizationMethod = (Element)nodosCanonicalizationMethod.item(0);
			String method = nodoCanonicalizationMethod.getAttribute(ALGORITHM);
			if (!URL_CANONICALIZATION.equals(method)) {
				esValido = false;
				log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR100) + ESPACIO + method);
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR100) + ESPACIO + method);
				return esValido;
			}
		}

		// Se obtiene el array de bytes de los nodos obtenidos
		byte[] byteData = null;
		try {
			byteData = UtilidadTratarNodo.obtenerByte(elementosSelloX);
		} catch (FirmaXMLError e) {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR16));
			log.error(e.getMessage(), e);
		}

		// Se obtiene el array de bytes del nodo EncapsulatedTimeStamp
		NodeList nodesEncapsulatedTimeStamp = selloTiempo.getElementsByTagNameNS(esquema, LIBRERIAXADES_ENCTIMESTAMP);

		if (nodesEncapsulatedTimeStamp.getLength() != 1) {
			// El nodo EncapsulatedTimeStamp dentro del sello de tiempo no existe o no es único
			esValido = false;
			log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + LIBRERIAXADES_ENCTIMESTAMP +
					I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_37) + ESPACIO + nodesEncapsulatedTimeStamp.getLength());
			resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + LIBRERIAXADES_ENCTIMESTAMP +
					I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_37) + ESPACIO + nodesEncapsulatedTimeStamp.getLength());
			return esValido;
		}

		Element encapsulatedTimeStampElement = (Element)nodesEncapsulatedTimeStamp.item(0);
		String encapsulatedTS = encapsulatedTimeStampElement.getFirstChild().getNodeValue();
		byte [] timeStampBytes = Base64.decode(encapsulatedTS);

		// Se comparan los resultados obtenidos
		try {
			tsv2 = TSCliente.validarSelloTiempo(byteData, timeStampBytes);
		} catch (NoSuchAlgorithmException e) {
			esValido = false;
			// Se ha producido un error al validar XADES-XL
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR16));
			log.error(e.getMessage(), e);
			return esValido;
		} catch (NoSuchProviderException e) {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR16));
			log.error(e.getMessage(), e);
			return esValido;
		} catch (CertStoreException e) {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR16));
			log.error(e.getMessage(), e);
			return esValido;
		} catch (TSPException e) {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR16));
			log.error(e.getMessage(), e);
			return esValido;
		} catch (IOException e) {
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR16));
			log.error(e.getMessage(), e);
			return esValido;
		} catch (TSClienteError e) {
			esValido = false;
			// El segundo sello de tiempo de la firma XADES-XL no tiene un formato correcto
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR17));
			log.error(e.getMessage(), e);
			return esValido;
		}

		if(!tsv2.isRespuesta())
		{
			esValido = false;
			// El segundo sello de tiempo de la firma XADES-XL no es válido
			log.info(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR15));
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR15));
			return esValido;
		}

		// Se guardan los resultados obtenidos
		Date fechaSello = tsv2.getFechaDate();
		if (fechaSello != null) {
			if (fechaSello.after(new Date(System.currentTimeMillis()))) {
				// La fecha del sello de tiempo es posterior a la actual
				esValido = false;
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR82));
				log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR82));
				return esValido;
			}
		}

		try {
			datosSelloTiempo.setFecha(fechaSello);
			datosSelloTiempo.setEmisor(tsv2.getEmisor());
			datosSelloTiempo.setAlgoritmo(TSPAlgoritmos.getAlgName(tsv2.getSelloAlg()));					
			datosSelloTiempo.setPrecision(tsv2.getPrecisionLong());
			datosSelloTiempo.setTipoSello(tipoSello);
			datosSelloTiempo.setTst(tsv2.getTst());
		} catch (Exception e) {
			// No se pudo generar los datos de la TSA
			esValido = false;
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR64), e);
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR64));
			return esValido;
		}

		arrayDatosSello.add(datosSelloTiempo);
		
		return true;
	}

	/**
	 * Valida que los certificados almacenados sin firmar se correspondan
	 * con los resúmenes firmados dentro del documento XADES-C
	 * En primera instancia, se leen y almacenan todos los nodos de XADES-C
	 * A continuación se sacan los ficheros .ocs de las URI´s y se validan contra la información de los nodos y/o los nodos CRLRefs
	 * Posteriormente se sacan los certificados .cer y se valida su encadenamiento, y se chequean contra los nodos
	 * Finalmente se valida que cada uno de los certificados esté asociado a una respuestaOCSP con estado good y ninguna a revoked
	 * @return Falso si no se corresponden los dos valores
	 * @throws FirmaXMLError Si no puede calcular el digest de los certificados almacenados
	 */
	private boolean validarXadesC(String path, String uriDS, X509Certificate certFirma) throws FirmaXMLError
	{
		NodeList completeCertificateRefs = null;
		NodeList completeRevocationRefs = null;

		// Coleccion de datos para los certificados
		ArrayList<String> certURI = null;
		ArrayList<String> digestAlg = null;
		ArrayList<String> digestValue = null;
		ArrayList<String> issuerName = null;
		ArrayList<String> issuerSerial = null;

		// Coleccion de datos para las respuestas OCSP
		ArrayList<String> ocspURI = null;
		ArrayList<OCSPResponderData> identifierOCSP = null;
		ArrayList<Date> identifierTime = null;
		ArrayList<String> ocspDigestAlg = null;
		ArrayList<String> ocspDigestValue = null;
		ArrayList<OCSPResp> respuestasOCSP = null; // Almacenará los .ocp recuperados de los ficheros o de los nodos RevocationValues

		// Colección de datos para CRLRefs
		ArrayList<String> crlURI = null;
		ArrayList<String> crlDigestAlg = null;
		ArrayList<String> crlDigestValue = null;
		ArrayList<String> crlIssuer = null;
		ArrayList<Date> crlIssuerTime = null;
		ArrayList<BigInteger> crlNumber = null;
		ArrayList<X509CRL> crlList = null; // Almacenará los .crl recuperados de los ficheros o de los nodos RevocationValues

		// Se mira que exista el nodo CompleteCertificateRefs y el nodo CompleteRevocationRefs


		completeCertificateRefs = firmaAValidar.getElementsByTagNameNS(esquema, LIBRERIAXADES_COMPLETECERTIFICATEREFS);
		completeRevocationRefs = firmaAValidar.getElementsByTagNameNS(esquema, LIBRERIAXADES_COMPLETEREVOCATIONREFS);

		if (completeCertificateRefs.getLength() == 0  || completeRevocationRefs.getLength() == 0) {
			log.debug(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_29)); // No se encuentra CompleteCertificateRefs o CompleteRevocationRefs
			resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_29));
			esValido = false;
			return esValido;
		}

		// A continuación se sacan los Certificados del nodo CertRefs
		Node certRefs = (Node)completeCertificateRefs.item(0).getFirstChild();

		// Si ha encontrado el nodo CertRefs, se pasa a capturar su contenido
		if (certRefs != null)
		{
			// Se saca la lista de certificados
			NodeList certs = certRefs.getChildNodes();
			int l = certs.getLength();

			certURI = new ArrayList<String>(l);
			digestAlg = new ArrayList<String>(l);
			digestValue = new ArrayList<String>(l);
			issuerName = new ArrayList<String>(l);
			issuerSerial = new ArrayList<String>(l);

			for (int i=0; i<l && esValido; i++)
			{
				// Sacamos los nodos Cert uno por uno
				Element certificate = (Element)certs.item(i); // Sacamos cert

				if (certificate != null) {
					// Obtenemos su URI, si existe, y la almacenamos
					String uri = null;
					try {
						uri = URLDecoder.decode(certificate.getAttributes().getNamedItem(URI).getNodeValue(), UTF8);
					} catch (UnsupportedEncodingException e) {
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR30));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR31));
					} catch (Exception e) {
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR65));
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR65));
					}
					if (uri != null)
						certURI.add(uri);
					
					// y del nodo, sacamos su digest y su issuer

					Element certDigest = (Element)certificate.getElementsByTagNameNS(esquema, LIBRERIAXADES_CERTDIGEST).item(0);	// Sacamos CertDigest

					Node algorithm = certDigest.getElementsByTagNameNS(uriDS, LIBRERIAXADES_DIGEST_METHOD).item(0);				// Sacamos DigestAlgorithm
					Node value = certDigest.getElementsByTagNameNS(uriDS, LIBRERIAXADES_DIGESTVALUE).item(0);					// Sacamos DigestValue

					digestAlg.add(algorithm.getAttributes().getNamedItem(ALGORITHM).getNodeValue()); 	// Guardamos el valor del algoritmo        			
					digestValue.add(value.getFirstChild().getNodeValue()); 								// Guardamos valor del digest

					Element issuer = (Element)certificate.getElementsByTagNameNS(esquema, LIBRERIAXADES_ISSUER_SERIAL).item(0); 	// Sacamos IssuerSerial
					Node name = issuer.getElementsByTagNameNS(uriDS, LIBRERIAXADES_X_509_ISSUER_NAME).item(0);					// Sacamos el nombre del emisor
					Node serial = issuer.getElementsByTagNameNS(uriDS, LIBRERIAXADES_X_509_SERIAL_NUMBER).item(0); 				// Sacamos el serial del emisor

					issuerName.add(name.getFirstChild().getNodeValue());   			// Guardmaos el issuerName
					issuerSerial.add(serial.getFirstChild().getNodeValue()); 		// Guardamos el issuerSerialNumber
				}
			}					
		}

		// A continuación se sacan las referencias OCSP del nodo OCSPRefs
		Node ocspRefs = (Node)firmaAValidar.getElementsByTagNameNS(esquema, OCSP_REFS).item(0);
		//Node ocspRefs = (Node)completeRevocationRefs.item(0).getFirstChild();

		// Si ha encontrado el nodo OCSPRefs, se pasa a capturar su contenido
		if (ocspRefs != null && esValido)
		{
			// Se saca la lista de referencias
			NodeList refs = ocspRefs.getChildNodes();
			int l = refs.getLength();

			ocspURI = new ArrayList<String>(l);
			identifierOCSP = new ArrayList<OCSPResponderData>(l);
			OCSPResponderData responderData = null;
			identifierTime = new ArrayList<Date>(l);
			ocspDigestAlg = new ArrayList<String>(l);
			ocspDigestValue = new ArrayList<String>(l);
			String noURIOCSPidentifier = I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR32) + 
			ESPACIO + I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR62);
			
			for (int i=0; i<l && esValido; i++)
			{
				// Sacamos los nodos OCSPRef uno por uno
				Element ocspRef = (Element)refs.item(i); // Sacamos OCSPRef

				if (ocspRef != null) {

					NodeList list = ocspRef.getElementsByTagNameNS(esquema, LIBRERIAXADES_OCSP_IDENTIFIER);

					if (list.getLength() != 0) {
						// Obtenemos su URI y la almacenamos
						try {
							ocspURI.add(URLDecoder.decode((((Element)list.item(0)).getAttributes().getNamedItem(URI).getNodeValue()), UTF8));
						} catch (UnsupportedEncodingException e) {
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR30));
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR32));
						} catch (Exception e) {
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR30));
							esValido = false;
							resultado.setLog(noURIOCSPidentifier);
						}

						// y de él, sacamos su OCSPIdentifier y su digest
						try {
							Element certDigest = (Element)ocspRef.getElementsByTagNameNS(esquema, LIBRERIAXADES_OCSP_IDENTIFIER).item(0);	// Sacamos OCSPIdentifier
							Node responder = certDigest.getElementsByTagNameNS(esquema, LIBRERIAXADES_RESPONDER_ID).item(0);				// Sacamos ResponderId
							Node time = certDigest.getElementsByTagNameNS(esquema, LIBRERIAXADES_PRODUCED_AT).item(0);					// Sacamos ProducedAt

							responderData = new OCSPResponderData();
							if (SCHEMA_XADES_111.equals(esquema) || SCHEMA_XADES_122.equals(esquema)) {
								responderData.setIdentificador(responder.getFirstChild().getNodeValue());	// Guardamos el responderID
							}
							else {								
								Node responderBy = responder.getFirstChild();
								if (BY_NAME.equals(responderBy.getLocalName())) {
									responderData.setTipoResponder(TIPOS_RESPONDER.BY_NAME);
									try {
										X500Principal prin = new X500Principal(responderBy.getFirstChild().getNodeValue());
										responderData.setIdentificador(prin.getName()); // Guardamos el responderID
									} catch (IllegalArgumentException ex) {
										esValido = false;
										resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_23));
										log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR27), ex);
										return false;
									} catch (NullPointerException ex) {
										esValido = false;
										resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_23));
										log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR27), ex);
										return false;
									}
								} else if (BY_KEY.equals(responderBy.getLocalName())) {
									responderData.setTipoResponder(TIPOS_RESPONDER.BY_KEY);
									responderData.setIdentificador(responderBy.getFirstChild().getNodeValue());	// Guardamos el responderID
								} else {
									esValido = false;
									resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR91));
									log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR91));
									return false;
								}	
							}
							
							identifierOCSP.add(responderData);
							
							Date fecha = UtilidadFechas.parseaFechaXML(time.getFirstChild().getNodeValue());
							if (fecha != null)
								identifierTime.add(fecha); 		// Guardamos el producedAt
							else {
								log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR63));
								esValido = false;
								resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR40));
							}

							// TODO: el elemento Digest es opcional y podria no aparecer. Corregir (si no aparece no hay validación de la integridad de la respuesta OCSP)
							Element ocspDigest = (Element)ocspRef.getElementsByTagNameNS(esquema, LIBRERIAXADES_DIGESTALGVALUE).item(0); 	// Sacamos DigestAlgAndValue
							Node algorithm = ocspDigest.getElementsByTagNameNS(uriDS, LIBRERIAXADES_DIGEST_METHOD).item(0); 			// Sacamos DigestAlgorithm
							Node value = ocspDigest.getElementsByTagNameNS(uriDS, LIBRERIAXADES_DIGESTVALUE).item(0); 					// Sacamos DigestValue
							
							ocspDigestAlg.add(algorithm.getAttributes().getNamedItem(ALGORITHM).getNodeValue()); 	// Guardamos el valor del algoritmo
							ocspDigestValue.add(value.getFirstChild().getNodeValue()); 								// Guardamos valor del digest
						} catch (Exception ex) {
							log.error(es.mityc.firmaJava.libreria.utilidades.I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR66));
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR66));
						}
					}
					else {
						log.debug(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR72));
					}
				}
			}
		}

		// Se obtienen si existen los nodos CRLRefs
		Node crlRefs = null;

		if (firmaAValidar.getElementsByTagNameNS(esquema, LIBRERIAXADES_CRLREFS) != null) {
			crlRefs = (Node)firmaAValidar.getElementsByTagNameNS(esquema, CRL_REFS).item(0);
		}

		// Si ha encontrado el nodo CRLRefs, se pasa a capturar su contenido
		if (crlRefs != null && esValido)
		{
			// Se saca la lista de crl
			NodeList crls = crlRefs.getChildNodes();
			int l = crls.getLength();

			crlURI = new ArrayList<String>(l);
			crlDigestAlg = new ArrayList<String>(l);
			crlDigestValue = new ArrayList<String>(l);
			crlIssuer = new ArrayList<String>(l);
			crlIssuerTime = new ArrayList<Date>(l);
			crlNumber = new ArrayList<BigInteger>(l);

			for (int i=0; i<l; i++)
			{
				// Sacamos los nodos crl uno por uno
				Element crl = (Element)crls.item(i); // Sacamos CRLRef

				// y del nodo, sacamos su digest y su issuer
				if (crl != null) {
					Element crlDigest = (Element)crl.getElementsByTagNameNS(esquema, LIBRERIAXADES_DIGESTALGVALUE).item(0);	// Sacamos DigestAlgAndValue

					Node algorithm = crlDigest.getElementsByTagNameNS(uriDS, LIBRERIAXADES_DIGEST_METHOD).item(0);			// Sacamos DigestAlgorithm
					Node value = crlDigest.getElementsByTagNameNS(uriDS, LIBRERIAXADES_DIGESTVALUE).item(0);				// Sacamos DigestValue

					crlDigestAlg.add(algorithm.getAttributes().getNamedItem(ALGORITHM).getNodeValue()); 	// Guardamos el valor del algoritmo        			
					crlDigestValue.add(value.getFirstChild().getNodeValue()); 								// Guardamos valor del digest

					Element identifier = (Element)crl.getElementsByTagNameNS(esquema, LIBRERIAXADES_CRLIDENTIFIER).item(0); 	// Sacamos IssuerIdentifier
					try {
						crlURI.add(URLDecoder.decode(identifier.getAttributes().getNamedItem(URI).getNodeValue(), UTF8));	// Se obtiene la URI
					} catch (UnsupportedEncodingException e) {
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR30));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR33));
					} catch (Exception e) {
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR30));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR32));
					}					

					try {
						Node issuer = identifier.getElementsByTagNameNS(esquema, LIBRERIAXADES_ISSUER).item(0);					// Sacamos el Issuer
						Node issuerTime = identifier.getElementsByTagNameNS(esquema, LIBRERIAXADES_ISSUERTIME).item(0); 		// Sacamos el tiempo del Issuer
						Node number = identifier.getElementsByTagNameNS(esquema, LIBRERIAXADES_NUMBER).item(0); 				// Sacamos el numero de la CRL (opcional)

						String crlIssuerName = issuer.getFirstChild().getNodeValue();
						try {
							X500Principal prin = new X500Principal(crlIssuerName);
							crlIssuer.add(prin.getName());
						} catch (IllegalArgumentException ex) {
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_23));
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR44), ex);
							return false;
						} catch (NullPointerException ex) {
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_23));
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR44), ex);
							return false;
						}
						Date fecha = UtilidadFechas.parseaFechaXML(issuerTime.getFirstChild().getNodeValue());
						if (fecha != null) 
							crlIssuerTime.add(fecha);   	// Guardamos el issuerTime
						else {
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR63));
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR40));
						}

						if (number != null) {
							crlNumber.add(new BigInteger(number.getFirstChild().getNodeValue())); 				// Guardamos el Number
						}
					} catch (Exception ex) {
						log.error(es.mityc.firmaJava.libreria.utilidades.I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR66));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR66));
					}
				}
			}
		}


		NodeList certificateValues = null;
		NodeList revocationValues = null;

		certificateValues = firmaAValidar.getElementsByTagNameNS(esquema, CERTIFICATE_VALUES);
		revocationValues = firmaAValidar.getElementsByTagNameNS(esquema, REVOCATION_VALUES);

		// Si existen los nodos, se valida como XAdES-XL
		boolean certsYOcspInterno = false;
		if (certificateValues.getLength() != 0 && revocationValues.getLength() != 0) {
			certsYOcspInterno = true;
		} 

		// Se construye la ruta donde se encuentran los archivos 
		if (path != null && !path.endsWith(System.getProperty(FILE_SEPARATOR)))
				path = path + System.getProperty(FILE_SEPARATOR);

		// Se valida CompleteRevocationCerts, en primer lugar los nodos OCSPRef
		if (ocspDigestValue != null && ocspDigestValue.size() != 0 && esValido) {
			int ocspNum = ocspDigestValue.size();
			OCSPResponderData responderData = null;
			byte[] respuesta = null;
			RespuestaOCSP respuestaOCSP = null;
			respuestasOCSP = new ArrayList<OCSPResp>(ocspNum);
			for (int x=0; x < ocspNum && esValido; ++x) {
				if (certsYOcspInterno) {
					Element ocsp = null;
					if (ocspURI != null && ocspURI.size() == ocspNum)
						ocsp = UtilidadTratarNodo.getElementById(firmaAValidar.getElementsByTagNameNS(esquema, LIBRERIAXADES_OCSPVALUE), ocspURI.get(x).substring(1));
					if (ocsp == null) {
						ocsp = buscarRevocationValueOCSP(ocspDigestValue.get(x), ocspDigestAlg.get(x));
						if (ocsp == null) {
							log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR34));
							return esValido;
						} else 
							respuesta = Base64.decode(ocsp.getFirstChild().getNodeValue());
					} else {
						respuesta = Base64.decode(ocsp.getFirstChild().getNodeValue());
					}
				}
				else if (ocspURI != null && ocspURI.size() == ocspNum) {
					String pathFicheroOCSP = null;
					try {
						pathFicheroOCSP = URLDecoder.decode(ocspURI.get(x),UTF8);
					} catch (UnsupportedEncodingException e1) {
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR35),e1);
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR35));
					} catch (Exception e) {
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR30));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR32));
					}

					File ocspFile = new File(path + pathFicheroOCSP);
					FileInputStream fis = null;
					try {
						fis = new FileInputStream(ocspFile);
						respuesta = new byte[(int)ocspFile.length()];
						fis.read(respuesta);
					} catch (FileNotFoundException e) {
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8),e);
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR36));
					} catch (IOException e) {
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8),e);
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR37));
					} finally {
						if (fis != null)
							try {
								fis.close();
							} catch (IOException e) {
							}
					}
				} else {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR36));
				}
				
				// Se valida el Digest
				String digestOCSPResponse = null;
				if (esValido) {
					try
					{
						MessageDigest resumenCertificadoTemp = MessageDigest.getInstance(SHA_1); // TODO: Sacar el algoritmo del nodo
						byte[] resumenMensajeByte = resumenCertificadoTemp.digest(respuesta);
						digestOCSPResponse = new String(Base64Coder.encode(resumenMensajeByte));
					}
					catch (NoSuchAlgorithmException nsae)
					{
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_20));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_20));
					}

					if (!((ocspDigestValue.get(x)).equals(digestOCSPResponse))) {
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR38));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR38));
					}
				}

				// Reconstruimos la respuesta 
				OCSPResp resp = null;
				if (esValido) {
					try {
						resp = new OCSPResp(respuesta);
					} catch (IOException e) {
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8),e);
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR37));
					}
					BasicOCSPResp respuestaBasica = null;
					respuestaOCSP = new RespuestaOCSP();
					Date tiempoRespuesta = null;
					try {
						try {
							respuestaBasica = (BasicOCSPResp)resp.getResponseObject();
						} catch (ClassCastException e) {
							continue;
						}
						respuestaOCSP.setNroRespuesta(resp.getStatus());
						tiempoRespuesta =respuestaBasica.getProducedAt();
						
						//respuestaOCSP.setTiempoRespuesta(respuestaBasica.getProducedAt());
						ResponderID respID = respuestaBasica.getResponderId().toASN1Object();
						respuestaOCSP.setResponder(respID);
						respuestaBasica.getResponses();
					} catch (OCSPException e) {
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8),e);
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR37));
					}

					// y validamos responderId y producedAt
					
					responderData = identifierOCSP.get(x);
					if (!((responderData.getIdentificador()).equals(respuestaOCSP.getValorResponder()))) {
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR39));
					}
					
					// Si estamos en el esquema 1.3.2 o superior se debe validar el tipo de responder
					if (!(SCHEMA_XADES_111.equals(esquema) || SCHEMA_XADES_122.equals(esquema))) 
						if (!(responderData.getTipoResponder()).equals(respuestaOCSP.getTipoResponder())) {
							esValido = false;
							// No coincide el tipo de responder del servidor OCSP con el almacenado
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR112));
						}

					if (!((identifierTime.get(x)).equals(tiempoRespuesta))) {
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR40));
					}
					// Se almacena la respuesta para validar los certificados
					if (esValido) {
						respuestasOCSP.add(resp);
					}
				}
			}
		}

		// Se valida CRLRefs
		if (crlDigestValue != null && crlDigestValue.size() != 0 && esValido) {
			int crlNum = crlDigestValue.size();
			byte[] crl = null;
			X509CRL x509CRL = null;
			crlList = new ArrayList<X509CRL>(crlNum);
			for (int x=0; x < crlNum && esValido; ++x) {
				if (certsYOcspInterno) {
					Element crlValue = null;
					if (crlURI != null && crlURI.size() == crlNum)
						crlValue = UtilidadTratarNodo.getElementById(firmaAValidar.getElementsByTagNameNS(esquema, LIBRERIAXADES_CRLVALUE), crlURI.get(x).substring(1));
					if (crlValue == null) {
						crlValue = buscarRevocationValueCRL(crlDigestValue.get(x), crlDigestAlg.get(x));
						if (crlValue == null) {
							log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR41));
							return esValido;
						} else
							crl = Base64.decode(crlValue.getFirstChild().getNodeValue());
					} else
						crl = Base64.decode(crlValue.getFirstChild().getNodeValue());
				}
				else if (crlURI != null && crlURI.size() == crlNum) {
					File crlFile = new File(path + crlURI.get(x));
					BufferedInputStream fis = null;
					try {
						fis = new BufferedInputStream(new FileInputStream(crlFile));
						crl = new byte[(int)crlFile.length()];
						fis.read(crl);
					} catch (FileNotFoundException e) {
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8),e);
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR42));
					} catch (IOException e) {
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8),e);
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR42));
					} finally {
						if (fis != null)
							try {
								fis.close();
							} catch (IOException e) {
							}
					}
				} else {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR42));
				}

				// Se valida el Digest
				String digestCRLResponse = null;
				if (esValido) {
					try
					{
						MessageDigest resumenCRLTemp = MessageDigest.getInstance(SHA_1); // TODO: Sacar el algoritmo del nodo
						byte[] resumenMensajeByte = resumenCRLTemp.digest(crl);
						digestCRLResponse = new String(Base64Coder.encode(resumenMensajeByte));
					}
					catch (NoSuchAlgorithmException nsae)
					{
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_20));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_20));
					}

					if (!((crlDigestValue.get(x)).equals(digestCRLResponse))) {
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR43));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR43));
					}
				}

				// Reconstruimos la crl
				if (esValido) {
					ByteArrayInputStream bais = new ByteArrayInputStream(crl);
					CertificateFactory certificatefactory;
					try {
						certificatefactory = CertificateFactory.getInstance(X_509);
						x509CRL = (X509CRL)certificatefactory.generateCRL(bais);
					} catch (CertificateException e) {
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8),e);
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR23));
					} catch (CRLException e) {
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8),e);
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR44));
					}

					if (x509CRL != null) {

						// Se valida issuer
						if (!((crlIssuer.get(x)).equals(x509CRL.getIssuerX500Principal().getName()))) {
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR45));
						}

						// Se valida issuerTime
						Date time = x509CRL.getThisUpdate();

						if (!((crlIssuerTime.get(x)).equals(time))) {
							esValido = false;
							resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR46));
						}

						// se valida el número de CRL
						BigInteger numeroNodo = crlNumber.get(x); 	// Se recupera el numero de CRL escrito en el nodo		

						// Si existe el nodo number (opcional), se saca el número de CRL contenido en la URI
						if (numeroNodo != null) {
							BigInteger numeroRecuperado = null;
							DERInteger derInt = null;
							// AppPerfect: Falso positivo
							ASN1InputStream ais = new ASN1InputStream(x509CRL.getExtensionValue(CRL_NUMBER_OID));
							try {
								ais = new ASN1InputStream(((DEROctetString)ais.readObject()).getOctets());
								derInt = (DERInteger)ais.readObject();
							} catch (IOException e) {
								esValido = false;
								resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR47));
							}
							numeroRecuperado = derInt.getValue();

							if (!((numeroNodo).equals(numeroRecuperado))) {
								esValido = false;
								resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR48));
							}
						}
					}
				}
				// Se almacena la lista para validar los certificados
				if (esValido) 
					crlList.add(x509CRL);
			}
		}

		// Se valida CompleteCertificateRefs
		int numCert = digestValue.size();
		ArrayList<X509Certificate> certsDeURI = new ArrayList<X509Certificate> ();
		X509Certificate certificado = null;
		File certFile = null;
		X509Certificate certRaiz = null;
		for (int x=0; x < numCert && esValido; ++x) {
			if (certsYOcspInterno) {
				// El nodo referenciado por la URI puede estar en todo el documento
				Element certValue = null;
				if (certURI != null && certURI.size() == numCert)
					certValue = UtilidadTratarNodo.getElementById(firmaAValidar.getElementsByTagNameNS(esquema, LIBRERIAXADES_X509VALUE), certURI.get(x).substring(1));
				if (certValue == null) {
					certValue = buscarCertificateValue(issuerName.get(x), new BigInteger(issuerSerial.get(x)));
					if (certValue == null) {
						log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR49));
						return esValido;
					}
				}
				try {
					ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(certValue.getFirstChild().getNodeValue()));
					CertificateFactory cf = CertificateFactory.getInstance(X_509);
					certificado = (X509Certificate)cf.generateCertificate(bais);
				} catch (CertificateException e1) {
					// Error al instanciar la factoría de certificados
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR23));
				} 
			}
			else if (certURI != null && certURI.size() == numCert) {
				String pathUri = null;
				try {
					pathUri = URLDecoder.decode(certURI.get(x),UTF8);
				} catch (UnsupportedEncodingException e2) {
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR30),e2);
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR30));
				}
				certFile = new File(path + pathUri);
				try {
					FileInputStream fis = new FileInputStream(certFile);
					try
					{
						// Se obtiene el certificado en su formato del archivo de la URI
						CertificateFactory cf = CertificateFactory.getInstance(X_509);
						certificado = (X509Certificate)cf.generateCertificate(fis);
					} catch (CertificateException e1) {
						// Error al instanciar la factoría de certificados
						throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR23));
					} finally {
						if (fis != null) {
							try {
								// AppPerfect: Falso positivo
								fis.close();
							} catch (IOException e) {
							}
						}
					}
				} catch (FileNotFoundException e) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8),e);
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR50));
				}
			} else {
				log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
				esValido = false;
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR49));
			}

			// Se comprueba que el valor digest del nodo coincida con el digest de la uri
			String resumenCertificado =CADENA_VACIA;
			try
			{
				MessageDigest resumenCertificadoTemp = UtilidadFirmaElectronica.getMessageDigest(digestAlg.get(x));
				if (resumenCertificadoTemp == null) {
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_16));
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR52));
					return false;
				}
				byte[] resumenMensajeByte = resumenCertificadoTemp.digest(certificado.getEncoded());
				resumenCertificado = new String(Base64Coder.encode(resumenMensajeByte));
			} catch (CertificateEncodingException e) {
				log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_23) + e.getMessage());				
				esValido = false;
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR52));
			}

			if (!(digestValue.get(x).equals(resumenCertificado))) {
				esValido = false;
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR53));
			}

			// Se comprueba que coincidan los numeros de serie
			if (!(issuerSerial.get(x).equals(certificado.getSerialNumber().toString()))) {
				esValido = false;
				resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR54));
			}

			if (esValido) {
				certsDeURI.add(certificado);
				if (certificado.getSubjectX500Principal().equals(certificado.getIssuerX500Principal()))
					certRaiz = certificado;
			}
		}

		// Se valida que los certificados se correspondan con la cadena de firma
		// Chequea issuer y serial, y posteriormente digest, excluyendo el primero (certificado de firma)
		cadenaCertificados.addAll(certsDeURI);
		ArrayList<ArrayList<X509Certificate>> certChains = UtilidadCertificados.getCertPathsArray(cadenaCertificados);
		if (certChains.size() > 1) {
			// No se pueden validar dos o más cadenas de certificados
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR84));
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR84));
			return false;
		} else {
			cadenaCertificados = certChains.get(0);
		}
		
		Iterator<X509Certificate> certGenIter = cadenaCertificados.iterator();
		ArrayList<X509Certificate> cadenaClon = new ArrayList<X509Certificate> (cadenaCertificados);
		// Excluimos el primero
		cadenaClon.remove(0);
		certGenIter.next();
		
		int certRefLenght = digestValue.size();
		while (certGenIter.hasNext())
		{				
			X509Certificate certAValidar = (X509Certificate)certGenIter.next();
			
			for (int i=0; i < certRefLenght && esValido; i++)
			{
				String issuer = issuerName.get(i);
				BigInteger serial = new BigInteger(issuerSerial.get(i));
				String alg = digestAlg.get(i);
				byte[] value = Base64Coder.decode(digestValue.get(i));

				if ((issuer).equals(certAValidar.getIssuerX500Principal().getName()) && 
						(serial).equals(certAValidar.getSerialNumber())) {
					// Cálculo del digest del certificado de firma
					MessageDigest haseador = UtilidadFirmaElectronica.getMessageDigest(alg);
					byte[] digestCert = null;
					try {
						digestCert = haseador.digest(certAValidar.getEncoded());
					} catch (CertificateEncodingException e) {
						// No se puede codificar un certificado de la cadena para calcular su digest
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR52));
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR23), e);
						return false;
					}
					if (Utilidades.isEqual(digestCert, value)) {
						// Coincidencia, se saca el certificado de la lista
						cadenaClon.remove(certAValidar);
						break;
					}
				}
			}
		}
		
		if (cadenaClon.size() > 0) {
			// Invalido
			// No se puede validar un certificado de la cadena por falta de referencias
			esValido = false;
			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR67));
			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR67));
			return false;
		}
		
		// Se almacena la cadena de certificados validada
		datosFirma.setCadenaFirma(UtilidadCertificados.convertCertPath(cadenaCertificados));

		// Se continua con la validación de los certificados a traves de CompleteRevocationRefs
//		if ((esValido) && (certRaiz == null)) {
//			log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR55));
//			esValido = false;
//			resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR55));
//		}

		if (esValido)
		{
			int numCadenaCerts = cadenaCertificados.size();
			for (int i = 0; i < numCadenaCerts; i++ ) {
				X509Certificate certAValidar = (X509Certificate) cadenaCertificados.get(i);
				X509Certificate certIssuer = null;
				if (i < (numCadenaCerts - 1))
					certIssuer = (X509Certificate) cadenaCertificados.get(i+1);
				else
					certIssuer = certAValidar;

				CertificateID certificadoId = null;
				try {
					certificadoId = new CertificateID(CertificateID.HASH_SHA1, certIssuer, certAValidar.getSerialNumber());
				} catch (OCSPException ex) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_16) + ex.getMessage());
					esValido = false;
					resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR56));
					break;
				}

				// Por cada certificado se comprueba que exista al menos una respuestaOCSP good y ninguna revoked
				// o que el certificado no exista en ninguna lista de revocación de su mismo issuer 
				// o no exista RevocationRef asociada
				int good = 0;
				int revoked = 0;
				
				DatosOCSP datosOCSP = null;
				DatosCRL datosCRL = null;
				BasicOCSPResp basicOcsp = null;

				if (respuestasOCSP != null) {		// Se comprueba que la lista de respuestasOCSP no sea nula
					Iterator<OCSPResp> itRespOCSP = respuestasOCSP.iterator();
					boolean hasNext = itRespOCSP.hasNext();
					while (hasNext && esValido) {
						OCSPResp respuestaOCSP = itRespOCSP.next();
						try {
							basicOcsp = (BasicOCSPResp)respuestaOCSP.getResponseObject();
						} catch (OCSPException e) {
							// No se puede reconstruir la respuesta básica a partir de la respuesta OCSP leída
							log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR113), e);
							break;
						}
						hasNext = itRespOCSP.hasNext();
						SingleResp[] singleResps = basicOcsp.getResponses();
						int numSingleResps = singleResps.length;
						for (int j = 0; j < numSingleResps; ++j) {
							if (certificadoId.equals(singleResps[j].getCertID())) {
								Object obj = singleResps[j].getCertStatus();
								if (obj == null) {
									good++;
									datosOCSP = new DatosOCSP();
									datosOCSP.setResponderId(basicOcsp.getResponderId().toASN1Object());
									datosOCSP.setCertConsultado(certAValidar.getSubjectX500Principal().toString());
									datosOCSP.setFechaConsulta(basicOcsp.getProducedAt());
									datosOCSP.setRespuestaOCSP(respuestaOCSP);
									arrayDatosOCSP.add(datosOCSP);
								}
								else if (obj instanceof RevokedStatus) {
									revoked++;
									break;
								}
							}
						}
						if (revoked > 0)
							break;
					}
				}
				if (crlList != null) {				// Se comprueba que la lista de CRL no sea nula
					Iterator<X509CRL> itCRLList = crlList.iterator();
					boolean hasNext = itCRLList.hasNext();
					while (hasNext && esValido) {
						X509CRL x509CRL = itCRLList.next();
						hasNext = itCRLList.hasNext();
						// Si el certificado tiene el mismo issuer que la CRL
						if ((x509CRL.getIssuerX500Principal().getName()).equals(certIssuer.getSubjectX500Principal().getName())) {
							// se comprueba que el certificado no esté dentro de la lista
							if (x509CRL.getRevokedCertificate(certificado) == null) {
								good++;
								datosCRL = new DatosCRL();
								datosCRL.setIssuer(x509CRL.getIssuerX500Principal().getName());
								datosCRL.setFechaEmision(x509CRL.getThisUpdate());
								datosCRL.setFechaCaducidad(x509CRL.getNextUpdate());
								datosCRL.setX509CRL(x509CRL);
								arrayDatosCRL.add(datosCRL);
							} else {
								revoked++;
								break;
							}
						}
					}
					if (revoked > 0)
						break;
				}
				
				if ((revoked == 0) && (good == 0)) {
					if (!((certAValidar.getSubjectDN()).equals(certAValidar.getIssuerDN()))) {
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR67));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR67));
						break;
					}
				} else {
					if ((revoked > 0) || (good == 0)) {
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR57));
						esValido = false;
						resultado.setLog(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR57));
						break;
					} 
				}				
			}  
		}

		//TODO: si la firma es XL comprobar que el primer certificado en certificateValues es igual que el firmante

		return esValido;
	}
	
	/**
	 * Busca en CertificateValues un certificado encapsulado con el mismo issuer y serial Number que el parametrizado
	 * 
	 * @param certIssuer
	 * @param serialNumber
	 * @return Si se encontró coincidencia, se devuelve el elemento EncapsulatedX509Certificate. En caso contrario, un valor nulo
	 */
	private Element buscarCertificateValue(String certIssuer, BigInteger serialNumber) {
		
		// Se busca el nodo CertificateValues para obtener sus nodos hijo
		NodeList certificateValuesNodeList = firmaAValidar.getElementsByTagNameNS(esquema, CERTIFICATE_VALUES);
		int certLength = certificateValuesNodeList.getLength();
		
		for (int i = 0; i < certLength; ++i) {
			Element certificateValuesElement = (Element) certificateValuesNodeList.item(i);
			NodeList certificados = certificateValuesElement.getChildNodes();
			int certificadosLength = certificados.getLength();
			
			for (int j = 0; j < certificadosLength; ++j) {
				Element certElement = (Element) certificados.item(j);
				if (!(new NombreNodo(esquema, ENCAPSULATED_X_509_CERTIFICATE).equals(
						new NombreNodo(certElement.getNamespaceURI(), certElement.getLocalName())))) { 
					// Al menos existe un nodo hijo de CertificateValues que no es del tipo EncapsulatedX509Certificate
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR114));
					return null;
				}
				
				// Se obtiene su valor para recontruir el certificado
				X509Certificate certificado = null;
				String digest = certElement.getFirstChild().getNodeValue();
				if (digest != null) {
					byte[] data = null;
					try {
						 data = Base64Coder.decode(digest);
					} catch (IllegalArgumentException ex) {
						// Contenido base64 de EncapsulatedX509Certificate inválido
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR115), ex);
						break;
					}
					ByteArrayInputStream bais = new ByteArrayInputStream(data);
					CertificateFactory cf = null;
					try {
						cf = CertificateFactory.getInstance(X_509);
						certificado = (X509Certificate)cf.generateCertificate(bais);
					} catch (CertificateException e) {
						// No se pudo generar el certificado a partir del Digest EncapsulatedX509Certificate leído
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR116), e);
						break;
					}
				} else {
					// No se pudo recuperar el contenido del nodo EncapsulatedX509Certificate
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR117));
					return null;
				}
				
				String issuerLeido = certificado.getIssuerX500Principal().getName();
				BigInteger serialNumberLeido = certificado.getSerialNumber();
				
				// Si coinciden los valores, se devuelve el EncapsulatedX509Certificate encontrado
				if (certIssuer.equals(issuerLeido) && serialNumber.equals(serialNumberLeido))
					return certElement;
			}
		}
		
		return null;
	}

	/**
	 * Busca en RevocationValues una respuesta OCSP encapsulada que de el mismo valor de digest
	 * 
	 * @param digest .- Digest que debe resultar del nodo a buscar
	 * @param method .- Algoritmo a utilizar para el cálculo del digest
	 * @return Si se encontró coincidencia, se devuelve el elemento EncapsulatedOCSPValue. En caso contrario, un valor nulo
	 */
	private Element buscarRevocationValueOCSP(String digest, String method) {
		
		// Se busca el nodo RevocationValues
		NodeList revocationValuesNodeList = firmaAValidar.getElementsByTagNameNS(esquema, REVOCATION_VALUES);
		int revocationLength = revocationValuesNodeList.getLength();
		
		for (int i = 0; i < revocationLength; ++i) {
			// Se obtienen los hijos de OCSPValues para cada RevocationValue encontrado
			Element revocationValuesElement = (Element) revocationValuesNodeList.item(i);
			NodeList ocspValues = revocationValuesElement.getElementsByTagNameNS(esquema, OCSP_VALUES);
			if (ocspValues.getLength() != 1) {
				// El nodo OCSPValues no existe o no es único
				log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + OCSP_VALUES + ESPACIO +
						I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_37) + ESPACIO + ocspValues.getLength());
				return null;				
			}
			NodeList respuestasOCSP = ocspValues.item(0).getChildNodes();
			int respuestasOCSPLength = respuestasOCSP.getLength();
			
			for (int j = 0; j < respuestasOCSPLength; ++j) {
				// Se obtienen las respuestas OCSP encapsuladas y se calcula su Digest
				Element respuestaOCSPElement = (Element) respuestasOCSP.item(j);
				if (!(new NombreNodo(esquema, ENCAPSULATED_OCSP_VALUE).equals(
						new NombreNodo(respuestaOCSPElement.getNamespaceURI(), respuestaOCSPElement.getLocalName())))) { 
					// Al menos existe un nodo hijo de OCSPValues que no es del tipo EncapsulatedOCSPValue
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR118));
					return null;
				}
				
				byte[] data = null;
				String encapsulatedValue = respuestaOCSPElement.getFirstChild().getNodeValue();
				if (encapsulatedValue != null) {
					try {
						 data = Base64Coder.decode(encapsulatedValue);
					} catch (IllegalArgumentException ex) {
						// Contenido base64 de EncapsulatedOCSPValue inválido
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR119), ex);
						break;
					}			
				} else {
					// No se pudo recuperar el contenido de EncapsulatedOCSPValue
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR120));
					return null;
				}
				// Se calcula el digest con el mismo algoritmo que el OCSP buscado
				MessageDigest resumenTemp = UtilidadFirmaElectronica.getMessageDigest(method);
				byte[] resumenMensajeByte = resumenTemp.digest(data);
				String digestLeido = new String(Base64Coder.encode(resumenMensajeByte));
				
				// Si coinciden los valores, se devuelve el nodo encontrado
				if (digest.equals(digestLeido))
					return respuestaOCSPElement;
			}
		}
		
		return null;
	}
	
	/**
	 * Busca en RevocationValues una CRL encapsulada con el mismo digest
	 * 
	 * @param digest .- Digest que debe resultar del nodo a buscar
	 * @param method .- Algoritmo a utilizar para el cálculo del digest
	 * @return Si se encontró coincidencia, se devuelve el elemento EncapsulatedCRLValue. En caso contrario, un valor nulo
	 */
	private Element buscarRevocationValueCRL(String digest, String method) {
		
		// Se busca el nodo RevocationValues
		NodeList revocationValuesNodeList = firmaAValidar.getElementsByTagNameNS(esquema, REVOCATION_VALUES);
		int revocationLength = revocationValuesNodeList.getLength();
		
		for (int i = 0; i < revocationLength; ++i) {
			// Se obtienen los hijos de CRLValues para cada RevocationValue encontrado
			Element revocationValuesElement = (Element) revocationValuesNodeList.item(i);
			NodeList crlValues = revocationValuesElement.getElementsByTagNameNS(esquema, CRL_VALUES);
			if (crlValues.getLength() != 1) {
				// El nodo CRLValues no existe o no es único
				log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + CRL_VALUES + ESPACIO +
						I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_37) + ESPACIO + crlValues.getLength());
				return null;				
			}
			NodeList crls = crlValues.item(0).getChildNodes();
			int crlsLength = crls.getLength();
			
			for (int j = 0; j < crlsLength; ++j) {
				// Se obtienen las listas de revocación y se reconstruyen para calcular su Digest
				Element crlElement = (Element) crls.item(j);
				if (!(new NombreNodo(esquema, ENCAPSULATED_CRL_VALUE).equals(
						new NombreNodo(crlElement.getNamespaceURI(), crlElement.getLocalName())))) { 
					// Al menos existe un nodo hijo de CRLValues que no es del tipo EncapsulatedCRLValue
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR121));
					return null;
				}
				
				// Se obtiene el valor de la CRL
				byte[] data = null;
				String encapsulatedValue = crlElement.getFirstChild().getNodeValue();
				if (encapsulatedValue != null) {
					try {
						 data = Base64Coder.decode(encapsulatedValue);
					} catch (IllegalArgumentException ex) {
						// Contenido base64 de EncapsulatedCRLValue inválido
						log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR122), ex);
						break;
					}					
				} else {
					// No se pudo recuperar el contenido de EncapsulatedCRLValue
					log.error(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR123));
					return null;
				}
				// Se calcula el digest con el mismo algoritmo que la CRL buscada
				MessageDigest resumenTemp = UtilidadFirmaElectronica.getMessageDigest(method);
				byte[] resumenMensajeByte = resumenTemp.digest(data);
				String digestLeido = new String(Base64Coder.encode(resumenMensajeByte));
			
				// Si coinciden los valores, se devuelve el nodo encontrado
				if (digest.equals(digestLeido))
					return crlElement;
			}
		}
		
		return null;
	}
	
	/**
	 * Indica el tipo de firma que tiene el documento
	 * @return El nombre del tipo de firma
	 */
	private DatosTipoFirma tipoFirma(Element firma, String esquemaXAdES) throws BadFormedSignatureException
	{	
		DatosTipoFirma datosTipoFirma = new DatosTipoFirma();
 		boolean esXAdES_C = false;
 		boolean esXAdES_X = false;

 		// Tomaremos que, por defecto, la fima es de tipo XAdES-BES (a continuación se valida que así sea)
 		datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_BES);

 	// Se comprueba que la firma sea XAdES-BES buscando el nodo QualifyingProperties
 		ArrayList<Element> nodosObject = UtilidadTratarNodo.obtenerNodos(firma, null, new NombreNodo(SCHEMA_DSIG, OBJECT));
 		Iterator<Element> itObject = nodosObject.iterator();
 		int numQualifyingProperties = 0;
 		while (itObject.hasNext()) {
 	 		ArrayList<Element> nodosQualifyingProperties = UtilidadTratarNodo.obtenerNodos(itObject.next(), null, new NombreNodo(esquemaXAdES, LIBRERIAXADES_QUALIFYING_PROPERTIES));
 	 		numQualifyingProperties += nodosQualifyingProperties.size();
 		}
 		
 		if (numQualifyingProperties != 1) {
 			// El nodo QualifyingProperties no existe o no es único
 			log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + 
 					ConstantesXADES.ESPACIO + ConstantesXADES.LIBRERIAXADES_QUALIFYING_PROPERTIES + 
 					ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_37) + 
 					ConstantesXADES.ESPACIO + numQualifyingProperties);
 			throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR124));
 		} 

 	// Se comprueba que la firma sea XAdES-EPES buscando el nodo SignaturepolicyIdentifier
 		NodeList nodosSignaturePolicyIdentifier = firma.getElementsByTagNameNS(
 				esquemaXAdES, ConstantesXADES.SIGNATURE_POLICY_IDENTIFIER);
 		int numSignaturePolicyIdentifier = nodosSignaturePolicyIdentifier.getLength();

 		if (numSignaturePolicyIdentifier > 1) {
 			// El nodo SignaturePolicyIdentifier no es único
 			log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) +
 					ConstantesXADES.ESPACIO + ConstantesXADES.SIGNATURE_POLICY_IDENTIFIER + 
 					ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_38) + 
 					ConstantesXADES.ESPACIO + numSignaturePolicyIdentifier);
 			// Firma XAdES-EPES mal formada
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR125));
 		} else if (ConstantesXADES.SCHEMA_XADES_111.equals(esquemaXAdES) && numSignaturePolicyIdentifier < 1) {
 			// No se encuentra el nodo SignaturePolicyIdentifier
 			log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_33) + 
 					ConstantesXADES.ESPACIO + ConstantesXADES.SIGNATURE_POLICY_IDENTIFIER);
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR125));
 		} else if (numSignaturePolicyIdentifier == 1) 
 			datosTipoFirma.setEsXAdES_EPES(true);

 	// Se comprueba que la firma sea XAdES-T buscando el nodo SignatureTimeStamp
 		NodeList nodosSignatureTimeStamp = firma.getElementsByTagNameNS(
 				esquemaXAdES, ConstantesXADES.SIGNATURE_TIME_STAMP);
 		int numSignatureTimeStamp = nodosSignatureTimeStamp.getLength();

 		if (numSignatureTimeStamp > 0)
 			datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_T);

 	// Se comprueba que la firma sea XAdES-C buscando el nodo CompleteCertificateRefs y CompleteRevocationRefs
 		NodeList nodosCompleteCertificateRefs = firma.getElementsByTagNameNS(
 				esquemaXAdES, ConstantesXADES.COMPLETE_CERTIFICATE_REFS);
 		int numCompleteCertificateRefs = nodosCompleteCertificateRefs.getLength();
 		NodeList nodosCompleteRevocationRefs = firma.getElementsByTagNameNS(
 				esquemaXAdES, ConstantesXADES.COMPLETE_REVOCATION_REFS);
 		int numCompleteRevocationRefs = nodosCompleteRevocationRefs.getLength();

 		if (numCompleteCertificateRefs > 1 || numCompleteCertificateRefs != numCompleteRevocationRefs) {
 			if (numCompleteCertificateRefs > 1) {
 				// El nodo CompleteCertificateRefs no es único
 				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + 
 						ConstantesXADES.ESPACIO + ConstantesXADES.COMPLETE_CERTIFICATE_REFS + 
 						ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_38) + 
 						ConstantesXADES.ESPACIO + numCompleteCertificateRefs);
 			} else {
 				// El nodo CompleteRevocationRefs no es único
 				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_36) + 
 						ConstantesXADES.ESPACIO + ConstantesXADES.COMPLETE_REVOCATION_REFS + 
 						ConstantesXADES.ESPACIO + I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_38) + 
 						ConstantesXADES.ESPACIO + numCompleteRevocationRefs);
 			}
 			// Firma XAdES-C mal formada
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR126));
 		} else if (numCompleteCertificateRefs == 1 && numCompleteCertificateRefs == numCompleteRevocationRefs) {
 			if (ConstantesXADES.SCHEMA_XADES_111.equals(esquemaXAdES) && !EnumFormatoFirma.XAdES_T.equals(datosTipoFirma.getTipoXAdES())) {
 				// La firma es una XAdES-C mal formada porque carece del nivel XAdES-T en el esquema 1.1.1
 				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR130));
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR126));
 			} else {
 				esXAdES_C = true;
 				datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_C);
 			}
		}
		
 	// Se comprueba que la firma sea XAdES-A buscando los nodos ArchiveTimeStamp, CertificateValues y RevocationValues
 		NodeList nodosArchiveTimeStamp = firma.getElementsByTagNameNS(
 				esquemaXAdES, ConstantesXADES.ARCHIVE_TIME_STAMP);
 		int numArchiveTimeStamp = nodosArchiveTimeStamp.getLength();
 		NodeList nodosCertificateValues = firma.getElementsByTagNameNS(
 				esquemaXAdES, ConstantesXADES.CERTIFICATE_VALUES);
 		int numCertificateValues = nodosCertificateValues.getLength();
 		NodeList nodosRevocationValues = firma.getElementsByTagNameNS(
 				esquemaXAdES, ConstantesXADES.REVOCATION_VALUES);
 		int numRevocationValues = nodosRevocationValues.getLength();

 		if (numArchiveTimeStamp > 0) {
 			if (numCertificateValues < 1 || numRevocationValues < 1) {
 				// La firma es una XAdES-A mal formada porque carece de los nodos Certificatevalues y/o RevocationValues 
 				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR131));
 				// Firma XAdES-A mal formada
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR127));
 			} else if (numCertificateValues > 1 || numRevocationValues > 1) {
 				// La firma es una XAdES-A mal formada porque los nodos Certificatevalues y/o RevocationValues no son únicos 
 				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR132));
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR127));
 			} else if (ConstantesXADES.SCHEMA_XADES_111.equals(esquemaXAdES) && !esXAdES_C) {
 				// La firma es una XAdES-A mal formada porque carece del nivel XAdES-C en el esquema 1.1.1
 				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR133));
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR127));
 			} else
 				datosTipoFirma.setEsXAdES_A(true);
 		}

 	// Se comprueba que la firma sea XAdES-X buscando los nodos SigAndRefsTimeStamp y/o RefsOnlyTimeStamp
 		NodeList nodosSigAndRefTimeStamp = firma.getElementsByTagNameNS(
 				esquemaXAdES, ConstantesXADES.SIG_AND_REFS_TIME_STAMP);
 		int numSigAndRefsTimeStamp = nodosSigAndRefTimeStamp.getLength();
 		NodeList nodosRefsOnlyTimeStamp = firma.getElementsByTagNameNS(
 				esquemaXAdES, ConstantesXADES.REFS_ONLY_TIME_STAMP);
 		int numRefsOnlyTimeStamp = nodosRefsOnlyTimeStamp.getLength();

 		if (numSigAndRefsTimeStamp > 0 || numRefsOnlyTimeStamp > 0) {
 			if (!esXAdES_C) {
 				// La firma es una XAdES-X mal formada porque carece del nivel XAdES-C
 				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR134));
 				// Firma XAdES-X mal formada
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR128));
 			} else {
 				esXAdES_X = true;
 				datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_X);
 			}
 		}

 	// Se comprueba que la firma sea XAdES-XL buscando los nodos CertificateValues y RevocationValues (ya buscados al validar XAdES-A)

 		if (numCertificateValues > 1 || numRevocationValues > 1) {
 			// La firma es una XAdES-A mal formada porque los nodos Certificatevalues y/o RevocationValues no son únicos 
 			log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR132));
 			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR127));
 		} else if (numCertificateValues == 1 && numRevocationValues == 1) {
 			// Si es XAdES-X y tiene los Values --> es XAdES-XL
 			// Si no es XAdES-X, tiene los Values y es XAdES-A --> No es XL pero no salta excepción (es XAdES-A)
 			// Si no es XAdES-X ni XAdES-A pero sí tiene los Values --> Excepción! es una XL mal formada 
 			if (esXAdES_X) {
 				datosTipoFirma.setTipoXAdES(EnumFormatoFirma.XAdES_XL);
 			} else if (!datosTipoFirma.esXAdES_A()) {
 				// La firma es una XAdES-XL mal formada porque carece del nivel XAdES-X y no es XAdES-A
 				log.error(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR135));
 				// Firma XAdES-XL mal formada
 				throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_VALIDARFIRMA_ERROR129));
 			}
 		} 

 		log.debug(datosTipoFirma.getTipoXAdES());
 		return datosTipoFirma;
	}
	
	/**
	 * Saca del nodo SigningTime los datos de la fecha de firma.
	 * Si falla el parseo de la firma porque no tiene un formato correcto devuelve un nulo
	 * @return Date fechaFirma
	 */
	
	private Date obtenerFechaFirma() {
        // Buscamos la fecha de la firma

        NodeList nodesSignTimeValue = null;
        Date fechaFirma = null; 

		nodesSignTimeValue = firmaAValidar.getElementsByTagNameNS(esquema, LIBRERIAXADES_SIGNINGTIME);
  	                          
        if(nodesSignTimeValue.getLength() != 0)
        {
        	Element stElement = (Element)nodesSignTimeValue.item(0);
        	String fecha =  stElement.getFirstChild().getNodeValue() ;
        	
			fechaFirma = UtilidadFechas.parseaFechaXML(fecha);
        }
        
        if (fechaFirma == null) {
			log.warn(I18n.getResource(LIBRERIAXADES_VALIDARFIRMA_ERROR63));
		}
        return fechaFirma;
    }
	
	/**
	 * Obtiene los roles del nodo ClaimedRoles
	 * @return ArrayList<String> roles
	 */
	private ArrayList<String> obtenerRoles (EstructuraFirma estructuraFirma) {
		// Buscamos el valor de los roles
		ArrayList<String> roles =  new ArrayList<String>();

		ArrayList<Element> lst = UtilidadTratarNodo.obtenerNodos(estructuraFirma.signedSignatureProperties, null, new NombreNodo(estructuraFirma.esquema, SIGNER_ROLE));
		Iterator<Element> it = lst.iterator();
		while (it.hasNext()) {
			NodeList nodesClaimedRoles = it.next().getElementsByTagNameNS(esquema, LIBRERIAXADES_CLAIMEDROLE);

			int nodesClaimedRolesLength = nodesClaimedRoles.getLength();
			for (int i=0; i<nodesClaimedRolesLength; i++)
			{
				Element stElement = (Element)nodesClaimedRoles.item(i);
				roles.add(stElement.getTextContent());
			}
		}

		return (roles.size() > 0) ? roles : null;
	}
	
	/**
	 * Saca del nodo QualifyingProperties el esquema. 
	 * Devuelve nulo si no esta en la lista de esquemas que se pueden validar.
	 * @return String esquema
	 */
	private EstructuraFirma obtenerEsquema(Element firma)
	{
		String esquema = null;
		for (Iterator<String> it=esquemasParaValidar.iterator(); it.hasNext( ); )
		{
			esquema = ((String)it.next()).trim();
			// identifica el nodo QualifyingProperties
	 		Element qualifyingElement = null;
	 		ArrayList<Element> nodosObject = UtilidadTratarNodo.obtenerNodos(firma, null, new NombreNodo(ConstantesXADES.SCHEMA_DSIG, ConstantesXADES.OBJECT));
	 		Iterator<Element> itObject = nodosObject.iterator();
	 		while (itObject.hasNext()) {
	 	 		ArrayList<Element> nodosQualifyingProperties = UtilidadTratarNodo.obtenerNodos(itObject.next(), null, new NombreNodo(esquema, ConstantesXADES.LIBRERIAXADES_QUALIFYING_PROPERTIES));
	 	 		if (nodosQualifyingProperties.size() > 0) {
	 	 			qualifyingElement = nodosQualifyingProperties.get(0);
	 	 			break;
	 	 		}
	 		}

			if (qualifyingElement != null) {
				EstructuraFirma ef = new EstructuraFirma();
				ef.firma = firma;
				ArrayList<Element> signedProperties = UtilidadTratarNodo.obtenerNodos(qualifyingElement, null, new NombreNodo(esquema, ConstantesXADES.SIGNED_PROPERTIES));
				if (signedProperties.size() != 1)
					return null;
				ArrayList<Element> signedSignatureProperties = UtilidadTratarNodo.obtenerNodos(signedProperties.get(0), null, new NombreNodo(esquema, ConstantesXADES.SIGNED_SIGNATURE_PROPERTIES));
				if (signedSignatureProperties.size() != 1)
					return null;
				ef.signedSignatureProperties = signedSignatureProperties.get(0);
				ArrayList<Element> unsignedProperties = UtilidadTratarNodo.obtenerNodos(qualifyingElement, null, new NombreNodo(esquema, ConstantesXADES.UNSIGNED_PROPERTIES));
				if (unsignedProperties.size() != 1)
					ef.unsignedSignatureProperties = null;
				else {
					ArrayList<Element> unsignedSignatureProperties = UtilidadTratarNodo.obtenerNodos(unsignedProperties.get(0), null, new NombreNodo(esquema, ConstantesXADES.UNSIGNED_SIGNATURE_PROPERTIES));
					if (unsignedSignatureProperties.size() != 1)
						ef.unsignedSignatureProperties = null;
					else
						ef.unsignedSignatureProperties = unsignedSignatureProperties.get(0);
				}
				ef.esquema = esquema;
				return ef;
			}
		}
		return null;
	}
}
