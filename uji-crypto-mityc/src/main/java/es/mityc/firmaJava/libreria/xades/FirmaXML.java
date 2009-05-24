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

package es.mityc.firmaJava.libreria.xades ;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Authenticator;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.IgnoreAllErrorHandler;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Attr;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import es.mityc.firmaJava.configuracion.Configuracion;
import es.mityc.firmaJava.configuracion.EnumFormatoFirma;
import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.errores.ClienteError;
import es.mityc.firmaJava.libreria.excepciones.AddXadesException;
import es.mityc.firmaJava.libreria.utilidades.Base64Coder;
import es.mityc.firmaJava.libreria.utilidades.GetPKCS12Keys;
import es.mityc.firmaJava.libreria.utilidades.I18n;
import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.utilidades.SimpleAuthenticator;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFechas;
import es.mityc.firmaJava.libreria.utilidades.UtilidadFirmaElectronica;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.errores.BadFormedSignatureException;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;
import es.mityc.firmaJava.libreria.xades.errores.PolicyException;
import es.mityc.firmaJava.ocsp.OCSPCliente;
import es.mityc.firmaJava.ocsp.OCSPClienteError;
import es.mityc.firmaJava.ocsp.RespuestaOCSP;
import es.mityc.firmaJava.ocsp.RespuestaOCSP.TIPOS_RESPONDER;
import es.mityc.firmaJava.policy.IFirmaPolicy;
import es.mityc.firmaJava.policy.PoliciesManager;
import es.mityc.firmaJava.ts.TSCliente;
import es.mityc.firmaJava.ts.TSClienteError;

/**
 * Clase principal para la firma de documentos XML
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class FirmaXML implements ConstantesXADES
{
    static Log log = LogFactory.getLog(FirmaXML.class);

    String 			profileDirectory 	= CADENA_VACIA;
    Configuracion 	configuracion 		= null ;
    private String 	xadesNS 			= null;
    private String	xadesSchema			= null;
    private String 	xmldsigNS 			= null;
    private boolean isSelloXTipo1		= true;
    private List<String> 	esquemasParaValidar = new LinkedList<String>();
    private String 	esquema 			= null;
    private boolean	estadoProxy 		= false;
    private String 	servidorProxy 		= null;
    private int		numeroPuertoProxy	= 8080;
    private String 	servidorTSA 		= null;
    private String 	algoritmoTSA 		= null;
    private String 	servidorOCSP 		= null;
    private boolean	isProxyAuth			= false;
    private String	proxyUser			= null;
    private String	proxyPass			= null;
    final static private String	DIR_OCSP = "./RespuestasOCSP";
    final static private String	DIR_CERTS = "./Certificados";
    
    // Almacena las id´s para el esquema 1.1.1
    private ArrayList<String> idNodoSelloTiempo = new ArrayList<String>();
    private String idNodoCertificateRefs = null;
    private String idNodoRevocationRefs = null;
    
    /**
     * Crea una nueva instancia de FirmaXML con la configuración proporcionada
     */
    public FirmaXML(Configuracion configuracion) {
        this.configuracion 	= configuracion ;
        this.xadesNS		= configuracion.getValor(XML_XADES_NS);
        this.xadesSchema	= configuracion.getValor(XADES_SCHEMA);
        this.xmldsigNS		= configuracion.getValor(XML_NS);
        this.isSelloXTipo1	= configuracion.comparar(ConstantesXADES.IS_SELLO_X_TIPO_1);
        final String cadenaDeUrisXadesNS = configuracion.getValor(VALIDAR_XADES_SCHEMA);

        StringTokenizer uriXadesNS = new StringTokenizer(cadenaDeUrisXadesNS, COMA);
        boolean valor = uriXadesNS.hasMoreTokens();
        while(valor)
        {
        	esquema = uriXadesNS.nextToken().trim();
        	esquemasParaValidar.add(esquema);
        	valor = uriXadesNS.hasMoreTokens();
        }

    	//Establece el idioma según la configuración
    	String locale = configuracion.getValor(LOCALE);
        // Configura el idioma
        I18n.setLocale(locale, locale.toUpperCase());
        
        // Datos del servidor proxy
        this.estadoProxy = configuracion.comparar(IS_PROXY);
        this.servidorProxy = configuracion.getValor(PROXY_SERVER_URL);
        final String puertoProxy = configuracion.getValor(PROXY_PORT_NUMBER);
        this.isProxyAuth = configuracion.comparar(IS_PROXY_AUTH);
        this.proxyUser = configuracion.getValor(PROXY_USER);
        this.proxyPass = configuracion.getValor(PROXY_PASS);
    	try
    	{
    		this.numeroPuertoProxy = Integer.parseInt(puertoProxy);
    	}
    	catch (Exception e)
    	{
   		log.warn(I18n.getResource(LIBRERIAXADES_FIRMAMSL_WARN_1));
    	}
        // Datos del servidor TSA
        this.servidorTSA = configuracion.getValor(TIME_STAMP_SERVER_URL) ;
        this.algoritmoTSA = configuracion.getValor(TIME_STAMP_HASH_ALG) ;

        // Datos del servidor OCSP
        this.servidorOCSP = configuracion.getValor(OCSP_SERVER_URL) ;
    }

    /**
     * Firma un fichero XML
     * 
     * @param numeroSerial Numero de serie del certificado firmante
     * @param emisorDN Emisor del certificado firmante
     * @param firmaCertificados X509Certificate para la firma digital
     * @param xml Documento XML a firmar
     * @return Array de bytes con la firma digital
     * @throws java.lang.Exception En caso de error
     */
    public boolean signFile(BigInteger numeroSerial, String emisorDN,
            X509Certificate firmaCertificados,
            File xml,
            String destino,
            String nombreArchivo) throws Exception{
    	FileInputStream fis = new FileInputStream(xml);
        return signFile(numeroSerial,
                emisorDN,
                firmaCertificados,
                fis,
                null,
                null,
                null,
                true,
                destino,
                nombreArchivo);
    }

    public Document signDoc(BigInteger numeroSerie, String emisorDN,
            X509Certificate certificadoFirma,
            Document xml) throws Exception {

    	Object[] res = signDoc(numeroSerie, emisorDN, certificadoFirma, xml, null, null, null, true);


    	// Si se firma XADES-C exclusivamente, se guardan las respuestaOCSP y los certificados 
        // con un nombre asociado al fichero de firma y en la misma ruta temporal     
        if (res[1] != null) {
        	throw new AddXadesException("Formato XAdES-C no válido con este método");
        } 
        
        return (Document) res[0];
    }

    /**
     * Firma un fichero XML
     * 
     * @param numeroSerial Numero de serie del certificado firmante
     * @param emisorDN emisor del certificado firmante
     * @param firmaCertificados Certificado de firma
     * @param xml Datos XML a firmar
     * @param salida OutputStream para escribir la salida generada
     * @throws Exception En caso de Error
     */
    public void signFile(BigInteger numeroSerial, String emisorDN,
            X509Certificate firmaCertificados,
            InputStream xml,
            OutputStream salida) throws Exception{
        signFile(numeroSerial,
                emisorDN,
                firmaCertificados,
                xml,
                null,
                null,
                null,
                salida,
                true);
    }

    /**
     * Firma un fichero XML
     * 
     * @param pk Clave privada del certificado firmante
     * @param firmaCertificado Certificado firmante
     * @param xml Fichero XML a firmar
     * @param directorioPerfil Directorio de configuracion de Firefox
     * @throws java.lang.Exception En caso de error
     * @return Array de bytes con el XML firmado
     */
    public boolean signFile(PrivateKey pk,
            X509Certificate firmaCertificado,
            File xml,
            String directorioPerfil,
            String destino,
            String nombreArchivo) throws Exception{
        this.profileDirectory = directorioPerfil ;
        FileInputStream fis = new FileInputStream(xml);
        return signFile(null,
                null,
                firmaCertificado,
                fis,
                null,
                null,
                pk,
                true,
                destino,
                nombreArchivo);
    }
    
    public Document signDoc(PrivateKey pk,
            X509Certificate certificadoFirma,
            Document doc,
            String directorioPerfil) throws Exception{
        this.profileDirectory = directorioPerfil ;
    	Object[] res = signDoc(null, null, certificadoFirma, doc, null, null, pk, true);


    	// Si se firma XADES-C exclusivamente, se guardan las respuestaOCSP y los certificados 
        // con un nombre asociado al fichero de firma y en la misma ruta temporal     
        if (res[1] != null) {
        	throw new AddXadesException("Formato XAdES-C no válido con este método");
        } 
        
        return (Document) res[0];
    }

    /**
      * Firma un fichero XML desde el explorador Mozilla Firefox
      * 
      * @param pk Clave privada para realizar la firma
      * @param firmaCertificado Certificado de firma
      * @param xml Datos XML a firmar
      * @param salida OutputStream para escribir la salida
      * @param directorioPerfil Directorio del perfil de Mozilla
      * @throws Exception En caso de error
      */
    public void signFile(PrivateKey pk,
            X509Certificate firmaCertificado,
            InputStream xml,
            OutputStream salida,
            String directorioPerfil
            
    ) throws Exception{
        this.profileDirectory = directorioPerfil ;
        signFile(null,
                null,
                firmaCertificado,
                xml,
                salida,
                null,
                null,
                pk,
                true);
    }

    /**
     * Firma un fichero XML
     * 
     * @param pkcs12Fichero
     * @param contraseña
     * @param xml Fichero con el XML a firmar
     * @param nodoRaizXml Nodo raíz de la firma
     * @param nodoXmlParaFirma Nodos a firmar
     * @return Boolean .- True si la firma se completó con éxito
     * @throws Exception En caso de error
     */
    public boolean signFile(String pkcs12Fichero,
            String contrasenia,
            File xml,
            String nodoRaizXml,
            String nodoXmlParaFirma,
            String destino,
            String nombreFichero) throws Exception{
   //     this.profileDirectory = profileDirectory ;
    	FileInputStream fis = new FileInputStream(xml);
        GetPKCS12Keys pkcs12 = new GetPKCS12Keys(pkcs12Fichero,contrasenia);
        return signFile(pkcs12.getCertificate().getSerialNumber(),
                pkcs12.getCertificate().getIssuerDN().toString() ,
                pkcs12.getCertificate(),
                fis,
                nodoRaizXml,
                nodoXmlParaFirma,
                pkcs12.getPrivateKey(),
                false,
                destino,
                nombreFichero);
    }

    /**
	 * Firma un fichero XML
	 * 
	 * @param numeroSerie Número de serie del certificado firmante
	 * @param emisorDN Emisor del certificado firmante
	 * @param certificadoFirma X509Certificate para la firma digital
	 * @param xml Fichero XML a firmar
	 * @param pk Clave privada del certificado firmante
	 * @param nodoRaizXml Elemento raiz del fichero XML a firmar donde se insertará la firma
	 * @param nodoParaFirmaXml Nodos XML a firmar separados por comas
	 * @throws java.lang.Exception En caso de error
	 */
	public void signFile(BigInteger numeroSerie, String emisorDN,
			X509Certificate certificadoFirma, InputStream xml, OutputStream salida, String nodoRaizXml,
			String nodoParaFirmaXml, PrivateKey pk, boolean navigator)
			throws Exception {

		//FileInputStream fis = (FileInputStream) xml;
		signFile(numeroSerie, emisorDN, certificadoFirma, xml, nodoRaizXml,
				nodoParaFirmaXml, pk, salida, navigator);
		}

	/**
	 * Firma un fichero XML
	 * 
	 * @param numeroSerie Número de serie del certificado firmante
	 * @param emisorDN Emisor del certificado firmante
	 * @param certificadoFirma X509Certificate para la firma digital
	 * @param xml Fichero XML a firmar
	 * @param nodoRaizXml Elemento raiz del fichero XML a firmar donde se insertará la firma
	 * @param nodoParaFirmaXml Nodos XML a firmar separados por comas
	 * @param pk Clave privada para realizar la firma
	 * @param salida OutputStream para escribir la salida
	 * @param navigator Tipo de navegador
	 * @throws Exception En caso de error
	 */
    public void signFile(BigInteger numeroSerie, String emisorDN, X509Certificate certificadoFirma,
            InputStream xml, String nodoRaizXml, String nodoParaFirmaXml,
            PrivateKey pk, OutputStream salida, boolean navigator) throws Exception{

    	Object[] res = signFile(numeroSerie, emisorDN, certificadoFirma, xml, nodoRaizXml, nodoParaFirmaXml, pk, navigator);

    	if (res[1] != null)
        	throw new ClienteError("Firma XAdES-C no soportada en este método") ;
        
        try
        {
        	XMLUtils.outputDOM((Document)res[0], salida, true);
        }
        catch (Throwable t)
        {
        	if (t.getMessage().startsWith(JAVA_HEAP_SPACE))
        		throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_3));
        	else
        		throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_4));
        }
    }
    
    /**
     * Firma un fichero XML
	 * 
     * @param numeroSerie Número de serie del certificado firmante
     * @param emisorDN Emisor del certificado firmante
     * @param certificadoFirma X509Certificate para la firma digital
     * @param xml Fichero XML a firmar
     * @param nodoRaizXml Elemento raiz del fichero XML a firmar donde se insertará la firma
     * @param nodoParaFirmaXml Nodos XML a firmar separados por comas
     * @param pk Clave privada para realizar la firma
     * @param navigator Tipo de navegador
     * @param destino Ruta de destino de la firma generada
     * @param nombreArchivo Nombre del archivo para salvar la firma generada
     * @return Boolean True si se realizó la firma correctamente
     * @throws Exception En caso de error
     */
    public boolean signFile(BigInteger numeroSerie, String emisorDN, X509Certificate certificadoFirma, 
    		InputStream xml, String nodoRaizXml, String nodoParaFirmaXml, 
    		PrivateKey pk, boolean navigator, String destino, String nombreArchivo) throws Exception {

    	if (destino == null || nombreArchivo == null) {
			// No se proporcionaron los datos de firma
			throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_31));
		}
    	
    	Object[] res = signFile(numeroSerie, emisorDN, certificadoFirma, xml, nodoRaizXml, nodoParaFirmaXml, pk, navigator);


    	// Si se firma XADES-C exclusivamente, se guardan las respuestaOCSP y los certificados 
        // con un nombre asociado al fichero de firma y en la misma ruta temporal     
    	Document doc = (Document) res[0];
        if (res[1] != null) {
        	doc = addURIXadesC(doc, saveOCSPFiles((ArrayList<RespYCerts>)res[1], destino, nombreArchivo));
        } 
        
        // Se guarda la firma en su destino
        File fichero = new File(destino + nombreArchivo); 
        FileOutputStream f = new FileOutputStream(fichero);
        
        try
        {
        	XMLUtils.outputDOM(doc, f,true);
        }
        catch (Throwable t)
        {
        	if (t.getMessage().startsWith(JAVA_HEAP_SPACE))
        		throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_3));
        	else
        		throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_4));
        } finally {
        	f.close(); 
        }

        return true ;
    }

    public Object[] signFile(BigInteger numeroSerie, String emisorDN, X509Certificate certificadoFirma, InputStream xml,
            String nodoRaizXml, String nodoParaFirmaXml, PrivateKey pk, boolean navigator) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.setErrorHandler(new IgnoreAllErrorHandler());

        InputSource isour = new InputSource(xml);
        String encoding = configuracion.getValor(ENCODING_XML) ;
        isour.setEncoding(encoding);
        Document doc = db.parse(isour);
        
        return signDoc(numeroSerie, emisorDN, certificadoFirma, doc, nodoRaizXml, nodoParaFirmaXml, pk, navigator);
    }
    
    public Object[] signDoc(BigInteger numeroSerie, String emisorDN, X509Certificate certificadoFirma, Document doc,
            String nodoRaizXml, String nodoParaFirmaXml, PrivateKey pk, boolean navigator) throws Exception {

    	ParametrosFirmaXML sp = ParametrosFirmaXML.getInstance() ;
    	Vector <X509Certificate> certRef = null;
    	byte[] respuestaOCSP = null;
		ArrayList<RespYCerts> respuestas = new ArrayList<RespYCerts>();
		
        if (navigator){
            if(numeroSerie!=null && emisorDN!=null)
            {
                sp.setIssuerDN(emisorDN);
                sp.setSerialNumber(numeroSerie);
            }
            else
            {
                sp.setModeSign(M) ;
                sp.setPerfilUsuario(this.profileDirectory);
            }

        }
        String nodosCadenaParaFirma ;
        if (nodoParaFirmaXml == null){
            nodosCadenaParaFirma= configuracion.getValor(XML_NODE_TO_SIGN);
        }else{
            nodosCadenaParaFirma = nodoParaFirmaXml;
        }
        StringTokenizer stTok = new StringTokenizer(nodosCadenaParaFirma,COMA);
        String[] nodosParaFirma = new String[stTok.countTokens()];
        int aa=0;
        boolean valor = stTok.hasMoreElements();
        while(valor){
            nodosParaFirma[aa] = ((String)stTok.nextElement()).trim();
            aa++;
            valor = stTok.hasMoreElements();
        }

        Init.init() ;
//        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
//        dbf.setNamespaceAware(true);
//        DocumentBuilder db = dbf.newDocumentBuilder();
//        db.setErrorHandler(new IgnoreAllErrorHandler());
//
//        InputSource isour = new InputSource(xml);
//        String encoding = configuracion.getValor(ENCODING_XML) ;
//        isour.setEncoding(encoding);
//        Document doc = db.parse(isour);

        Element elementoPrincipal = null;
        if (nodoRaizXml == null) {
        	elementoPrincipal = (Element)doc.getFirstChild();
        } else {
            NodeList nodos = doc.getElementsByTagName(nodoRaizXml);
            if(nodos.getLength() != 0)
                elementoPrincipal = (Element)nodos.item(0);
            else
                throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_2)) ;
        }
        
        XMLSignature.setDefaultPrefix(Constants.SignatureSpecNS,
                configuracion.getValor(XML_NS));
        XMLSignature firma = new XMLSignature(doc,
                CADENA_VACIA ,
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        firma.setId(configuracion.getValor(SIGNATURE_NODE_ID));
        firma.getSignedInfo().setId(configuracion.getValor(SIGNED_INFO_NODE_ID));

        firma.setXPathNamespaceContext(xmldsigNS, SCHEMA_DSIG);
        EnumFormatoFirma tipoFirma = configuracion.getFormatoXades();
        boolean xadesActivo = (tipoFirma.compareTo(EnumFormatoFirma.XAdES_BES)>=0);

        if(xadesActivo){
            firma.setXPathNamespaceContext(xadesNS, xadesSchema) ;
        }

        elementoPrincipal.appendChild(firma.getElement());
        if(xadesActivo){

        	String tipoEsquema = UtilidadFirmaElectronica.obtenerTipoReference(xadesSchema);
    		
            firma.addDocument(ALMOHADILLA +  configuracion.getValor(SIGNATURE_NODE_ID)
            + GUION_SIGNED_PROPERTIES,
                    null, Constants.ALGO_ID_DIGEST_SHA1,SIGNED_PROPERTIES_ID, tipoEsquema);
        }

        firma.addKeyInfo(certificadoFirma);
        firma.addKeyInfo(certificadoFirma.getPublicKey()) ;
        firma.getKeyInfo().setId(CERTIFICATE1) ;
        // Añadimos los elementos propios de la firma en XADES
        
        
        for (int a=0;a< nodosParaFirma.length ; a++) {
        	if (MENOR_ROOT_MAYOR.equalsIgnoreCase(nodosParaFirma[a])) {
        		Transforms trans = new Transforms(doc);
        		trans.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
	            firma.addDocument(CADENA_VACIA,
	                    trans,
	                    Constants.ALGO_ID_DIGEST_SHA1);
        	} else {
        		StringBuffer sb = new StringBuffer(ALMOHADILLA);
        		sb.append(nodosParaFirma[a]);
	            firma.addDocument(String.valueOf(sb),
	                    null,
	                    Constants.ALGO_ID_DIGEST_SHA1);
        	}
        }

        if(xadesActivo){

            addXades(doc,
                    configuracion.getValor(SIGNATURE_NODE_ID),
                    certificadoFirma,
                    firma.getElement());
        	XAdESSchemas schema = XAdESSchemas.getXAdESSchema(xadesSchema);
        	if (schema == null) {
        		log.error("Esquema XAdES desconocido: " + xadesSchema);
        		throw new AddXadesException("Esquema de XAdES desconocido");
        	}
            if ((configuracion.comparar(ConstantesXADES.LIBRERIAXADES_ADD_EPES)) || (schema.equals(XAdESSchemas.XAdES_111)))  {
            	addXadesEPES(firma.getElement());
            }

        }

        // Si firmamos con Microsoft tenemos que generar una clave privada
        // para utilizar como parámeto. Sin embargo, esta clave
        // no se utiliza para la firma.
        // Mirar la implementación de SignatureSpi en MCUSignatureMS
        if(sp.getSerialNumber()!=null && sp.getIssuerDN() !=null)
        {
        	
            KeyPairGenerator kpgPalote = KeyPairGenerator.getInstance(RSA);
            try
            {
            	firma.sign(kpgPalote.genKeyPair().getPrivate());
            }
            catch (Throwable t)
            {
            	log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_32), t);
            	if (t.getMessage().startsWith(JAVA_HEAP_SPACE))
            		throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_3));
            	else if (t.getMessage().startsWith(FIRMA_NO_CONTIENE_DATOS))
            		throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_1));
            	else
            		throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_4));
            }

        }
        else
        {
            // Si es mozilla utilizamos la clave privada real
            try
            {
            	firma.sign(pk);
            }
            catch (Throwable t)
            {
            	log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_4), t);
            	if (t.getMessage().startsWith(JAVA_HEAP_SPACE))
            		throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_3));
            	else if (t.getMessage().startsWith(FIRMA_NO_CONTIENE_DATOS))
            		throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_1));
            	else
            		throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_4));
            }
        }

        // Añadimos el Id al nodo signature value
 
    	Element elementoValorFirma = null ;
        
        NodeList nodoValorFirma = doc.getElementsByTagNameNS(SCHEMA_DSIG, SIGNATURE_VALUE);
        if(nodoValorFirma.getLength() != 0)
            elementoValorFirma = (Element)nodoValorFirma.item(0);
        else
            throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_5));
        // Le añadimos el elemento ID
        Attr idValorFirma = doc.createAttribute(ID);
        idValorFirma.setValue(SIGNATURE_VALUE);
        NamedNodeMap elementoIdAtributosValorFirma =
                elementoValorFirma.getAttributes();
        elementoIdAtributosValorFirma.setNamedItem(idValorFirma);


        //Comprobamos si se debe de firmar añadiendo el elemento de XADES-T
        
        boolean xadesT =(tipoFirma.compareTo(EnumFormatoFirma.XAdES_T)>=0); 

        log.debug(I18n.getResource(LIBRERIAXADES_FIRMAXML_DEBUG_1) + xadesT);

        if(xadesT) {

            try
            {
            	// Añadimos XADES-T

            	if (servidorTSA!=null && !servidorTSA.trim().equals(CADENA_VACIA))
            	{
                	// Obtenemos la respuesta del servidor TSA
	                TSCliente tsCli = null;
	                if(estadoProxy)
	                {
						System.setProperty("http.proxyHost", servidorProxy);
						System.setProperty("http.proxyPort", Integer.toString(numeroPuertoProxy));
						if (isProxyAuth) {
							Authenticator.setDefault(new SimpleAuthenticator(proxyUser, proxyPass));
						} 
						else {
							Authenticator.setDefault(null);
						}
	                }
                    tsCli = new TSCliente(servidorTSA,algoritmoTSA);

	                // Se añaden los elementos propios de la firma XADES-T
	                byte[] byteSignature = UtilidadTratarNodo.obtenerByteNodo(doc, SCHEMA_DSIG, SIGNATURE_VALUE);
	                addXadesT(doc,configuracion.getValor(SIGNATURE_NODE_ID),tsCli.generarSelloTiempo(byteSignature)) ;
            	}
            	else
            	{
            		throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_6));
            	}
            }
            catch (AddXadesException e)
            {
                throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_7) + e.getMessage()) ;
            }
        }

        RespuestaOCSP respuesta = null;
        
        // Comprobamos si se debe de firmar añadiendo los elementos de XADES-C
        boolean xadesC = (tipoFirma.compareTo(EnumFormatoFirma.XAdES_C)>=0);
        log.debug(I18n.getResource(LIBRERIAXADES_FIRMAXML_DEBUG_2) + xadesC);
        
        if(xadesC){

        	respuesta = new RespuestaOCSP();
        	try
        	{

        		// Comprobamos si se ha realizado antes la firma XADES-T. En caso contrario se le avisa
        		// al usuario que no puede realizarse la firma XADES-C
        		if(xadesT){
        			// Añadimos XADES-C

        			if (servidorOCSP!=null && !servidorOCSP.trim().equals(CADENA_VACIA))
        			{
        				// Obtenemos la respuesta del servidor OCSP
        				String tiempoRespuesta = CADENA_VACIA;
        				OCSPCliente ocspCliente = null;
        				RespYCerts bloque = null;
        				try
        				{
        					if(estadoProxy)
        					{
        						System.setProperty("http.proxyHost", servidorProxy);
        						System.setProperty("http.proxyPort", Integer.toString(numeroPuertoProxy));
        						if (isProxyAuth) {
        							Authenticator.setDefault(new SimpleAuthenticator(proxyUser, proxyPass));
        						} 
        						else {
        							Authenticator.setDefault(null);
        						}
        					}
    						ocspCliente = new OCSPCliente(servidorOCSP);

        					respuesta = ocspCliente.validateCert(certificadoFirma);
        					tiempoRespuesta = UtilidadFechas.formatFechaXML(respuesta.getTiempoRespuesta());
        				}
        				catch (OCSPClienteError ex)
        				{
        					throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8) + ex.getMessage()) ;
        				}

        				// Solo continúa si el certificado es válido
        				if (respuesta.getNroRespuesta()!=0)
        				{
        					throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_9)) ;
        				}

        				certRef = respuesta.getRefCerts();
        				respuestaOCSP = respuesta.getRespuesta();

        				bloque = new RespYCerts();
        				bloque.setRespOCSP(respuestaOCSP);
        				bloque.setX509Cert(certificadoFirma);
        				bloque.setTiempoRespuesta(tiempoRespuesta);
        				bloque.setResponder(respuesta.getValorResponder(), respuesta.getTipoResponder());
        				respuestas.add(bloque);

        				int certRefSize = certRef.size();
        				for (int x=1; x < certRefSize; ++x) {
        					X509Certificate certificado = certRef.get(x);
        					
        					try {
        						respuesta = ocspCliente.validateCert(certificado);
        						tiempoRespuesta = UtilidadFechas.formatFechaXML(respuesta.getTiempoRespuesta());
        					}
        					catch (OCSPClienteError ex)
        					{
        						throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8) + ex.getMessage()) ;
        					}
        					// Solo continúa si el certificado es válido
        					if (respuesta.getNroRespuesta()!=0)
        					{
        						throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_9)) ;
        					}
        					respuestaOCSP = respuesta.getRespuesta();
        					bloque = new RespYCerts();
            				bloque.setRespOCSP(respuestaOCSP);
            				bloque.setX509Cert(certificado);
            				bloque.setTiempoRespuesta(tiempoRespuesta);
            				bloque.setResponder(respuesta.getValorResponder(), respuesta.getTipoResponder());
            				respuestas.add(bloque);
        				}

        				// Se añaden los elementos propios de la firma XADES-C
        				addXadesC(doc, respuestas);
        			}
        		} 
        		else
    	        {
    	        	throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_24)) ;
    	        }
        	}
        	catch (AddXadesException e)
        	{
        		throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_10) + e.getMessage()) ;
        	}
        }
        
        // Comprobamos si se debe de firmar añadiendo los elementos de XADES-X
        boolean xadesX = (tipoFirma.compareTo(EnumFormatoFirma.XAdES_X)>=0);
        log.debug(I18n.getResource(LIBRERIAXADES_FIRMAXML_DEBUG_3) + xadesX);
        
        boolean xadesXL = (tipoFirma.compareTo(EnumFormatoFirma.XAdES_XL)==0);
        log.debug(I18n.getResource(LIBRERIAXADES_FIRMAXML_DEBUG_4) + xadesXL);
        			
        xadesXL = xadesX;	// Si es XAdES-X, se pone xades-XL a true para redondear
        
        if(xadesX){
           	// Para realizar la firma XADES-XL se deben completar antes los
           	// formatos de firmas XADES-T y XADES-C

        	if (xadesT && xadesC ) {
        		
        		// Se obtiene el nodo raíz de la firma
        		Element signatureElement = firma.getElement();
        		if (!(new NombreNodo(SCHEMA_DSIG, SIGNATURE).equals(
        				new NombreNodo(signatureElement.getNamespaceURI(), signatureElement.getLocalName())))) {
        			// No se encuentra el nodo Signature
        			throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_33) + ESPACIO + SIGNATURE);
        		}
        		
        		// A partir del nodo raíz de la firma se obtiene el nodo UnsignedSignatureProperties
        		Element unsignedSignaturePropertiesElement = null;
        		NodeList unsignedSignaturePropertiesNodes = 
        			signatureElement.getElementsByTagNameNS(xadesSchema, UNSIGNED_SIGNATURE_PROPERTIES);
        		
        		if (unsignedSignaturePropertiesNodes.getLength() != 1) {
        			// El nodo UnsignedSignatureProperties no existe o no es único 
        			log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + UNSIGNED_SIGNATURE_PROPERTIES +
    						ESPACIO + I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_37) + ESPACIO +
    						unsignedSignaturePropertiesNodes.getLength());
        			// El sistema no soporta nodos UnsignedSignatureProperties múltiples
        			throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_41));
        		} else
        			unsignedSignaturePropertiesElement = (Element)unsignedSignaturePropertiesNodes.item(0);
        		
        		// Se añaden los elementos propios de la firma XADES-X
        		if (isSelloXTipo1) 
        			addXadesX(unsignedSignaturePropertiesElement);
        		else 
        			addXadesX2(unsignedSignaturePropertiesElement);
        	}
        	else
	        {
	        	throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_25)) ;
	        }
        }
	
        if(xadesXL){
           	// Para realizar la firma XADES-XL se deben completar antes los
           	// formatos de firmas XADES-T, XADES-C y XADES-X

	        if (xadesT && xadesC && xadesX) {    	
	            try
	            {
	            	// Añadimos XADES-XL
	            	
	                addXadesXL(doc, respuestas);
	            }
	            catch (Exception e)
	            {
	                throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_12) + e.getMessage()) ;
	            }
	        }
	        else
	        {
	        	throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_13)) ;
	        }
        }
        
        Object[] res = new Object[2];
        res[0] = doc;
        if (xadesC && !xadesXL)
        	res[1] = respuestas;
        else
        	res[1] = null;
        
        return res;
    }

    /**      
     * Firma un fichero XML con multifirma.
     * 
     * @param serialNumber Número de serie del certificado firmante
     * @param issuerDN Emisor del certificado firmante
     * @param DOM documento
     * @param certificadoFirma X509Certificate para la firma digital
     * @param pk Clave privada del certificado firmante
     * @throws java.lang.Exception En caso de error
     * @return byte[] XMl firmado
     */
    public byte[] multiSignFile(BigInteger serialNumber,
    							String issuerDN,
    							Document doc,
            					X509Certificate certificadoFirma,
            					PrivateKey pk,
            					boolean navigator)
    throws Exception
    {
        // Comprobamos si ya existe el elemento counter signature
    	// Si ya existe, recuperamos la ultima ocurrencia de Signature value
    		// añadimos un nuevo elemento signature referenciando al anterior
    	// Si no existe, recuperamos el objeto signature value para obtener el id
    		// añadimos un nuevo elemento counter signature con un primer signature

    	// Recogemos el nodo <CounterSignature>
    	Element elementoContadorFirma = null ;
    	Element elementoPrincipal	  	= null ;
    	String ultimoId					= null ;
    	int certificadoId				= 0;
    	
    	
        NodeList firmaContadorNodo = doc.getElementsByTagNameNS(SCHEMA_DSIG, COUNTER_SIGNATURE);
        if(firmaContadorNodo.getLength() != 0)
        {
        	// Si ya existe, recuperamos la ultima ocurrencia de Signature value
    		// añadimos un nuevo elemento signature referenciando al anterior
            // Establecemos el nodo raíz en counter Signature.
            elementoContadorFirma = (Element)firmaContadorNodo.item(0);
            elementoPrincipal 			= elementoContadorFirma;

            // Iteramos sus nodos Signature para recuperar el ultimo
            NodeList firmas = elementoContadorFirma.getElementsByTagNameNS(SCHEMA_DSIG, SIGNATURE);
            if(firmas != null)
            {
	            Element ultimaFirma = (Element) firmas.item(firmas.getLength() - 1);

	            // Iteramos los hijos de la ultima firma para obtener el elemento signature value y sacar el Id
	            NodeList listaValorUltimaFirma = ultimaFirma.getElementsByTagNameNS(SCHEMA_DSIG, SIGNATURE_VALUE);
	            Element valorUltimaFirma 		= (Element) listaValorUltimaFirma.item(0);
	            ultimoId	 						= valorUltimaFirma.getAttribute(ID);

	            certificadoId = firmas.getLength();
            }
            else
            {
            	throw new ClienteError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_14));
            }
        }
        else
        {
        	// Si no existe, recuperamos el objeto signature value para obtener el id
    		// añadimos un nuevo elemento counter signature con un primer signature
        	// Recogemos el nodo <ds:SignatureValue>
            Element valorElementoFirma = null ;

            NodeList valorNodoFirma = doc.getElementsByTagNameNS(SCHEMA_DSIG, SIGNATURE_VALUE);
            if(valorNodoFirma.getLength() != 0) {
                valorElementoFirma = (Element)valorNodoFirma.item(0);
                ultimoId = valorElementoFirma.getAttribute(ID);
            }else {
                throw new Exception(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_15));
            }

            // Ahora creamos la estructura de Counter Signature para añadir la firma referenciada
            elementoContadorFirma = doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + COUNTER_SIGNATURE);
            
            
            NodeList caracteristicaSinFirmarFirmaNodo = doc.getElementsByTagNameNS(xadesSchema, UNSIGNED_SIGNATURE_PROPERTIES);
            Element elememtoSinFirmarCaracteristicaFirma = null;
            if(caracteristicaSinFirmarFirmaNodo.getLength() != 0)
            {
                elememtoSinFirmarCaracteristicaFirma = (Element)caracteristicaSinFirmarFirmaNodo.item(0);

                elememtoSinFirmarCaracteristicaFirma.appendChild(elementoContadorFirma);
            }

            // Actualiza el nodo de donde colgará la firma y el número de certificado. Por ser el primero sera el 0
            elementoPrincipal = elementoContadorFirma;
        }

        XMLSignature.setDefaultPrefix(Constants.SignatureSpecNS,
                configuracion.getValor(XML_NS));
        XMLSignature firma = new XMLSignature(doc,
                CADENA_VACIA ,
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        
        EnumFormatoFirma tipoFirma = configuracion.getFormatoXades();
        boolean xadesActivo = (tipoFirma.compareTo(EnumFormatoFirma.XAdES_BES)>=0);

        firma.setXPathNamespaceContext(xmldsigNS, SCHEMA_DSIG);
        if(xadesActivo){
            firma.setXPathNamespaceContext(xadesNS, xadesSchema) ;
        }
        firma.setId(configuracion.getValor(SIGNATURE_NODE_ID) + certificadoId);
        firma.getSignedInfo().setId(configuracion.getValor(SIGNED_INFO_NODE_ID) + certificadoId);
        firma.addKeyInfo(certificadoFirma);
        firma.addKeyInfo(certificadoFirma.getPublicKey()) ;
        
        firma.getKeyInfo().setId( CERTIFICATE + certificadoId) ;
        firma.addDocument(ALMOHADILLA + ultimoId,
                    null,
                    Constants.ALGO_ID_DIGEST_SHA1);

        ParametrosFirmaXML sp = ParametrosFirmaXML.getInstance() ;
        if (navigator){
            if(serialNumber!=null && issuerDN!=null) {
                sp.setIssuerDN(issuerDN);
                sp.setSerialNumber(serialNumber);
            }else{
                sp.setModeSign(M) ;
                sp.setPerfilUsuario(this.profileDirectory);
            }

        }
        // Si firmamos con microsoft tenemos que gererar una clave privada
        // que no se utiliza para la firma.
        // Mirar la implementacion de SignatureSpi en MCUSignatureMS
        if(sp.getSerialNumber()!=null && sp.getIssuerDN() != null){
            KeyPairGenerator kpgPalote = KeyPairGenerator.getInstance(RSA);
            firma.sign(kpgPalote.genKeyPair().getPrivate());
        }else{
            // Si es mozilla utilizamos la clave privada Real
            firma.sign(pk);
        }

        elementoPrincipal.appendChild(firma.getElement());
        
        // Ahora añadimos el id al nodo Signature Value
        NodeList nodesSignatureValue = elementoPrincipal.getElementsByTagNameNS(SCHEMA_DSIG, SIGNATURE_VALUE);
        Element lastSignatureValueElement = (Element)nodesSignatureValue.item(nodesSignatureValue.getLength() - 1);

        // Le añadimos el elemento ID
        // signatureValueElement
        Attr idSignatureValue = doc.createAttribute(ID);
        idSignatureValue.setValue( SIGNATURE + certificadoId);
        NamedNodeMap elementIdSignatureValueAttributes = lastSignatureValueElement.getAttributes();
        elementIdSignatureValueAttributes.setNamedItem(idSignatureValue);

        ByteArrayOutputStream f = new ByteArrayOutputStream();

        XMLUtils.outputDOM(doc, f, true);

        return f.toByteArray() ;
    }

    /**
     * Este método realiza la implementación de la firma XADES-BES
     * 
     * @param doc Documento de firma
     * @param firmaID Identificador del nodo de firma
     * @param firmaCertificado Certificado que realiza la firma
     * @param elementoPrincipalFirma Elemento principal del nodo de firma
     * @return Documento de firma con formato XADES-BES
     * @throws AddXadesException En caso de error
     */
    private Document addXades(Document doc,
            String firmaID,
            X509Certificate firmaCertificado,
            Element elementoPrincipalFirma) throws AddXadesException
            {

    	// Creamos el QualifyingProperties
        Element elemntQualifyingProperties = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + QUALIFYING_PROPERTIES);

        // Creamos los atributos de QualifyingProperties
        elemntQualifyingProperties.setAttributeNS(null, TARGET , ALMOHADILLA + firmaID);
        
        // Creamos el elemento SignedProperties
        Element propiedadesFirmadasElemento = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + SIGNED_PROPERTIES);

        // Creamos los atributos de SignedProperties
        propiedadesFirmadasElemento.setAttributeNS(null, ID, firmaID  + GUION_SIGNED_PROPERTIES);

        // Creamos el xades:SignedSignatureProperties
        Element propiedadesFirmadasElementoFirma = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + SIGNED_SIGNATURE_PROPERTIES);
        
        // Creamos el xades:SigningTime
        
        Element tiempoFirmaElemento = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + SIGNING_TIME);

        // Formatemos la fecha de acuerdo al estándar
        // http://www.w3.org/TR/2001/REC-xmlschema-2-20010502/#dateTime

        String tiempoFecha = UtilidadFechas.formatFechaXML(new Date());
        tiempoFirmaElemento.appendChild(doc.createTextNode(tiempoFecha));
     // Creamos el xades:SigningCertificate
        Element certificadoFirmaElemento = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + SIGNING_CERTIFICATE);

        // Creamos el xades:Cert
        Element certificadoElemento = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + CERT);

        // Creamos el xades:CertDigest
        Element resumenCertificadoElemento = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + CERT_DIGEST);


        // Creamos el xades:DigestMethod
        Element metodoResumenElemento = doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + DIGEST_METHOD);
        metodoResumenElemento.setAttributeNS(null, ALGORITHM, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1);

        // Creamos el xades:DigestValue
        String resumenCertificado =CADENA_VACIA;
        
        try {
            MessageDigest resumenCertificadoTemp = MessageDigest.getInstance(SHA_1);
            byte[] byteMessageDigest =resumenCertificadoTemp.digest(firmaCertificado.getEncoded());
            resumenCertificado = new String(Base64Coder.encode(byteMessageDigest));
        }
        catch (NoSuchAlgorithmException nsae)
        {
            throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_16));
        }
        catch (CertificateEncodingException cee)
        {
        	throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_17));
        }

        Element elementDigestValue = doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + DIGEST_VALUE);
        elementDigestValue.appendChild(doc.createTextNode(resumenCertificado));

        // Creamos el xades:IssuerSerial
        Element elementoEmisorSerial = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + ISSUER_SERIAL );

        // Creamos el xades:X509IssuerName
        Element elementoX509EmisorNombre = doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + X_509_ISSUER_NAME);
        elementoX509EmisorNombre.appendChild(doc.createTextNode(firmaCertificado.getIssuerX500Principal().getName()));

        // Creamos el xades:X509SerialNumber
        Element elementoX509NumeroSerial = doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + X_509_SERIAL_NUMBER);
        elementoX509NumeroSerial.appendChild(doc.createTextNode(firmaCertificado.getSerialNumber().toString()));

        // Creamos el xades:SignerRole. Para ello consultamos en el fichero de propiedades
        String rolesFirmante = configuracion.getValor(SIGNER_ROLES);
        boolean roleFirmante = false;
        Element elementoRoleFirmanteElemento = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + SIGNER_ROLE);
        
        if(!Configuracion.isEmpty(rolesFirmante))
        {
        	Element elementoRolesDemandadosElementos = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + CLAIMED_ROLES);
        	elementoRoleFirmanteElemento.appendChild(elementoRolesDemandadosElementos);

        	
        	// Añadimos un nuevo elemento SignerRoles
        	StringTokenizer roles = new StringTokenizer(rolesFirmante, COMA);
        	boolean valor = roles.hasMoreElements();
	        while(valor){
	        	String role = (String) roles.nextElement();
	        	Element elementClaimedRoleElement = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + CLAIMED_ROLE);
	        	elementClaimedRoleElement.appendChild(doc.createTextNode(role.trim()));
	        	elementoRolesDemandadosElementos.appendChild(elementClaimedRoleElement);
	        	valor = roles.hasMoreElements();
	        }
	        roleFirmante = true;
	    }
        
        propiedadesFirmadasElementoFirma.appendChild(tiempoFirmaElemento);
        propiedadesFirmadasElemento.appendChild(propiedadesFirmadasElementoFirma);

        resumenCertificadoElemento.appendChild(metodoResumenElemento);
        resumenCertificadoElemento.appendChild(elementDigestValue);

        certificadoElemento.appendChild(resumenCertificadoElemento);

        elementoEmisorSerial.appendChild(elementoX509EmisorNombre);
        elementoEmisorSerial.appendChild(elementoX509NumeroSerial);

        certificadoElemento.appendChild(elementoEmisorSerial);


        certificadoFirmaElemento.appendChild(certificadoElemento);

        propiedadesFirmadasElementoFirma.appendChild(certificadoFirmaElemento);


        if(roleFirmante)
        {
        	propiedadesFirmadasElementoFirma.appendChild(elementoRoleFirmanteElemento);
        }
        elemntQualifyingProperties.appendChild(propiedadesFirmadasElemento);

        // Añadimos el objeto final
        Element elementoObjeto = doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + OBJECT);
        elementoObjeto.setAttributeNS(null, ID, firmaID + GUION_OBJECT );

        elementoObjeto.appendChild(elemntQualifyingProperties);

        elementoPrincipalFirma.appendChild(elementoObjeto) ;
        return null;
    }
    
    private void addXadesEPES(Element elementoPrincipalFirma) throws AddXadesException {
    	// Se obtiene el manager para la política indicada
    	String confPolicyManager = configuracion.getValor(ConstantesXADES.LIBRERIAXADES_EPES_POLICY_MANAGER);
    	if (Configuracion.isEmpty(confPolicyManager))
    		confPolicyManager = ConstantesXADES.LIBRERIAXADES_IMPLIEDPOLICY_MANAGER;
    	IFirmaPolicy policyManager = PoliciesManager.getInstance().getEscritorPolicy(confPolicyManager);
    	if (policyManager == null) {
    		log.error("PolicyManager pedido no disponible: " + confPolicyManager);
    		throw new AddXadesException("Política configurada desconocida");
    	}
    	
    	XAdESSchemas schema = XAdESSchemas.getXAdESSchema(xadesSchema);
    	if (schema == null) {
    		log.error("Esquema XAdES desconocido: " + xadesSchema);
    		throw new AddXadesException("Esquema de XAdES desconocido");
    	}
    	
    	try {
    		policyManager.escribePolicy(elementoPrincipalFirma, xmldsigNS, xadesNS, schema);
    	} catch (PolicyException ex) {
    		log.error("Error escribiendo politica: " + ex.getMessage(), ex);
    		throw new AddXadesException(ex.getMessage(), ex);
    	}
    	
    }

    /**
     * Este método añade la implementación para XADES-T
     * 
     * @param doc Documento de firma con formato XADES-BES
     * @param firmaID Identificador del nodo de firma
     * @param selloTiempo Respuesta del servidor TSA con el sello de tiempo en formato binario
     * @return Documento de firma con formato XADES-T
     * @throws AddXadesException
     */
    private Document addXadesT(Document doc, String firmaID, byte[] selloTiempo)
    throws AddXadesException
    {

    	Element elementoPrincipal = null ;
    	NodeList nodos = doc.getElementsByTagNameNS(xadesSchema, QUALIFYING_PROPERTIES);
    	if(nodos.getLength() != 0)
    	{
    		elementoPrincipal = (Element)nodos.item(0);
    	}
    	else
    	{
    		throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_18)) ;
    	}
    	Element propiedadesElementosNoFirmados =
    		doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + UNSIGNED_PROPERTIES);

    	// Creamos los atributos de UnSignedProperties
    	Attr propiedadesNoFirmadasId = doc.createAttribute(ID);
    	propiedadesNoFirmadasId.setValue( firmaID  + GUION_UNSIGNED_PROPERTIES );
    	NamedNodeMap atributosSinFirmarPropiedadesElemento =
    		propiedadesElementosNoFirmados.getAttributes();
    	atributosSinFirmarPropiedadesElemento.setNamedItem(propiedadesNoFirmadasId);

    	Element propiedadesSinFirmarFirmaElementos =
    		doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + UNSIGNED_SIGNATURE_PROPERTIES);

    	// Se buscan otros sellos de tiempo en la firma y se les asigna una Id si no la tienen
    	NodeList sellosPreexistentes = doc.getElementsByTagNameNS(xadesSchema, SIGNATURE_TIME_STAMP);
    	int numSellos = sellosPreexistentes.getLength();
    	for (int i = 0; i < numSellos; ++i) {
    		Element sello = (Element) sellosPreexistentes.item(i);
    		String selloId = sello.getAttribute(ID);
    		if (selloId == null) {
    			Attr informacionElementoSigTimeStamp = doc.createAttribute(ID);
    			selloId = UtilidadTratarNodo.newID(doc, SELLO_TIEMPO);
    	    	informacionElementoSigTimeStamp.setValue(selloId);
    	    	sello.getAttributes().setNamedItem(informacionElementoSigTimeStamp);
    		}
    		// Se almacena su nombre de Id por si es preciso referenciarlos
    		idNodoSelloTiempo.add(selloId); 		
    	}
    	
    	// Se crea el nodo de sello de tiempo
    	Element tiempoSelloElementoFirma =
    		doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + SIGNATURE_TIME_STAMP);
	
    	// Se escribe una Id única
    	Attr informacionElementoSigTimeStamp = doc.createAttribute(ID);
    	String idSelloTiempo = UtilidadTratarNodo.newID(doc, SELLO_TIEMPO);
    	informacionElementoSigTimeStamp.setValue(idSelloTiempo);
    	idNodoSelloTiempo.add(idSelloTiempo);
    	tiempoSelloElementoFirma.getAttributes().setNamedItem(informacionElementoSigTimeStamp);
    	
    	// Se agrega un nodo Include con una URI apuntando a SignatureValue si es esquema 1.2.2
    	if (SCHEMA_XADES_122.equals(xadesSchema)) {
    		Element informacionElementoHashDatos = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + INCLUDE);

    		Attr informacionElementoHashDatosUri = doc.createAttribute(URI);
    		informacionElementoHashDatosUri.setValue(ALMOHADILLA_SIGNATURE_VALUE);

    		NamedNodeMap informacionAtributosElementoHashDatos =
    			informacionElementoHashDatos.getAttributes();
    		informacionAtributosElementoHashDatos.setNamedItem(informacionElementoHashDatosUri);
        	tiempoSelloElementoFirma.appendChild(informacionElementoHashDatos) ;
    	}
    	
    	Element tiempoSelloEncapsulado =
    		doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + ENCAPSULATED_TIME_STAMP);

    	tiempoSelloEncapsulado.appendChild(
    			doc.createTextNode(new String(Base64Coder.encode(selloTiempo))));

    	tiempoSelloElementoFirma.appendChild(tiempoSelloEncapsulado);

    	propiedadesSinFirmarFirmaElementos.appendChild(tiempoSelloElementoFirma);
    	propiedadesElementosNoFirmados.appendChild(propiedadesSinFirmarFirmaElementos);
    	elementoPrincipal.appendChild(propiedadesElementosNoFirmados);
    	return doc;
    }

    /**
     * Este método añade la implementacion para XADES-C
     * 
     * @param doc Documento de firma con formato XADES-T
     * @param respuestas Cadena de Certificación con las respuestas OCSP del certificado de firma
     * @return Documento de firma con formato XADES-C
     * @throws AddXadesException En caso de error
     */
    private Document addXadesC(Document doc,
    		ArrayList<RespYCerts> respuestas)
    throws AddXadesException
    {

    	// Recogemos el nodo UnsignedSignatureProperties del cual dependen los nodos
    	// que hay que añadir para completar la firma XADES-C
    	Element elementoPrincipal = null ;
    	ArrayList<X509Certificate> certRefs = null;

    	NodeList nodos = doc.getElementsByTagNameNS(xadesSchema, UNSIGNED_SIGNATURE_PROPERTIES);
    	if(nodos.getLength() != 0)
    	{
    		elementoPrincipal = (Element)nodos.item(0);
        }
        else
        {
            throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_19)) ;
        }
        

        // Aqui vienen las llamadas para los certificados
        Element certificadosElementosFirma =
                doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + COMPLETE_CERTIFICATE_REFS);
        Element revocacionesElementoFirma =
            doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + COMPLETE_REVOCATION_REFS);

        // Construye las referencias del certificado
        int size = respuestas.size();
        if (size > 0) {
        	certRefs = new ArrayList<X509Certificate> (size);
        	for(int x=0; x < size; ++x) {
        		certRefs.add((respuestas.get(x)).getX509Cert());
        	}
        }
        
        if(certRefs != null)
        {
        	// Se le agrega una Id única
        	Attr informacionElementoCertRef = doc.createAttribute(ID);
        	idNodoCertificateRefs = UtilidadTratarNodo.newID(doc, COMPLETE_CERTIFICATE_REFS);
        	informacionElementoCertRef.setValue(idNodoCertificateRefs);
        	certificadosElementosFirma.getAttributes().setNamedItem(informacionElementoCertRef);       		
        	
        	Element elementoCertRefs =
                doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + CERT_REFS);

        	certificadosElementosFirma.appendChild(elementoCertRefs);
        	int longitud = certRefs.size();
        	       	
        	for (int i=1; i<longitud; i++) // Se salta el primero porque es el certificado firmante
        	{
        		X509Certificate firmaCertificado = (X509Certificate) certRefs.get(i);
        		Element elementCertRef = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + CERT);
        		
        		// Creamos los atributos de UnSignedProperties
            	Attr uris = doc.createAttribute(URI);
            	// AppPerfect: Falso positivo. No son expresiones constantes
            	String idNueva = UtilidadTratarNodo.newID(doc, LIBRERIAXADES_CERT_PATH);
            	uris.setValue( ALMOHADILLA + idNueva );
            	respuestas.get(i).setIdCertificado(idNueva);
            	NamedNodeMap atributosURI = elementCertRef.getAttributes();
            	atributosURI.setNamedItem(uris);

    	        Element resumenElementoCert = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + CERT_DIGEST);

    	        // Creamos el xades:DigestMethod
    	        Element metodoResumenElemento = doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + DIGEST_METHOD);

    	        // Creamos los atributos de DigestMethod
    	        Attr propiedadesFirmaAlgoritmo = doc.createAttribute(ALGORITHM);
    	        propiedadesFirmaAlgoritmo.setValue(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1);
    	        NamedNodeMap cualidadesMetodoResumenElemento =
    	                metodoResumenElemento.getAttributes();
    	        cualidadesMetodoResumenElemento.setNamedItem(propiedadesFirmaAlgoritmo);

    	        // Creamos el xades:DigestValue
    	        String resumenCertificado =CADENA_VACIA;
    	        try
    	        {
    	            MessageDigest resumenCertificadoTemp = MessageDigest.getInstance(SHA_1);
    	            byte[] resumenMensajeByte =resumenCertificadoTemp.digest(firmaCertificado.getEncoded());
    	            resumenCertificado = new String(Base64Coder.encode(resumenMensajeByte));
    	        }
    	        catch (NoSuchAlgorithmException nsae)
    	        {
    	        	log.error(nsae);
    	        	throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_16));
    	        } catch (CertificateEncodingException e) {
    	        	log.error(e);
    	        	throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_23));				
    	        }

    	        Element elementDigestValue =
    	                doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + DIGEST_VALUE);
    	        elementDigestValue.appendChild(
    	                doc.createTextNode(resumenCertificado));

    	        // Creamos el xades:IssuerSerial
    	        Element elementoEmisorSerial =
    	                doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + ISSUER_SERIAL);
    	        // Creamos el xades:X509IssuerName
    	        Element elementoX509EmisorNombre =
    	                doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + X_509_ISSUER_NAME);
    	        elementoX509EmisorNombre.appendChild(
    	                doc.createTextNode(firmaCertificado.getIssuerX500Principal().getName()));

    	        // Creamos el xades:X509SerialNumber
    	        Element elementoX509NumeroSerial =
    	                doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + X_509_SERIAL_NUMBER);
    	        elementoX509NumeroSerial.appendChild(
    	                doc.createTextNode(firmaCertificado.getSerialNumber().toString()));

    	        //Add references
    	        elementoEmisorSerial.appendChild(elementoX509EmisorNombre);
    	        elementoEmisorSerial.appendChild(elementoX509NumeroSerial);

    	        resumenElementoCert.appendChild(metodoResumenElemento);
    	        resumenElementoCert.appendChild(elementDigestValue);

    	        elementCertRef.appendChild(resumenElementoCert);
    	        elementCertRef.appendChild(elementoEmisorSerial);

    	        elementoCertRefs.appendChild(elementCertRef);
        	}
        }

        // Construye el valor de la respuesta del servidor OCSP
        // bajo el nodo completo de la referencia de la revocación
    	Element elementOCSPRefs = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + OCSP_REFS);
    	
    	revocacionesElementoFirma.appendChild(elementOCSPRefs);
    	
    	Element elementOCSPRef = null;
    	String tiempoRespuesta = null;
    	byte[] mensajeRespuesta = null;
    	
        if (size > 0) {
        	// Se le agrega una Id única
        	Attr informacionElementoCertRef = doc.createAttribute(ID);
        	idNodoRevocationRefs = UtilidadTratarNodo.newID(doc, COMPLETE_REVOCATION_REFS);
        	informacionElementoCertRef.setValue(idNodoRevocationRefs);
        	revocacionesElementoFirma.getAttributes().setNamedItem(informacionElementoCertRef);       		
        	
        	for(int x=0; x < size; ++x) {
        		
        		RespYCerts respYCert = respuestas.get(x);

        		tiempoRespuesta = respYCert.getTiempoRespuesta();
        		TIPOS_RESPONDER tipoResponder = respYCert.getTipoResponder();
        		String valorResponder = respYCert.getResponderID();
        		mensajeRespuesta = respYCert.getRespOCSP();

        		elementOCSPRef = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + OCSP_REF);
        		
        		// Creamos los atributos de UnSignedProperties
        		String idNueva = UtilidadTratarNodo.newID(doc, OCSP);
            	respYCert.setIdOCSP(idNueva);

        		Element identificadorElementoOCSP = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + OCSP_IDENTIFIER);
            	Attr uris = doc.createAttribute(URI);
            	uris.setValue( ALMOHADILLA + idNueva );
            	NamedNodeMap atributosURI = identificadorElementoOCSP.getAttributes();
            	atributosURI.setNamedItem(uris);

        		// Creamos el xades:DigestMethod
        		Element elementoRespondedorId = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + RESPONDER_ID);

        		
        		Element responderFinal = elementoRespondedorId;
        		if (!(SCHEMA_XADES_111.equals(xadesSchema)) && !(SCHEMA_XADES_122.equals(xadesSchema))) {
        			Element hijo = null;
        			if (tipoResponder.equals(TIPOS_RESPONDER.BY_NAME)) {
        				hijo = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + BY_NAME);
        			}
        			else {
        				hijo = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + BY_KEY);
        			}
        			// TODO: tener en cuenta que podria no ser ninguno de estos valores en un futuro
            		elementoRespondedorId.appendChild(hijo);
            		responderFinal = hijo;
        		}
        		responderFinal.appendChild(doc.createTextNode(valorResponder));		

        		Element elementoProdujoEn = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + PRODUCE_AT);

        		elementoProdujoEn.appendChild(doc.createTextNode(tiempoRespuesta));

        		identificadorElementoOCSP.appendChild(elementoRespondedorId);
        		identificadorElementoOCSP.appendChild(elementoProdujoEn);
        		Element valorYResumenElemento = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + DIGEST_ALG_AND_VALUE);

        		// Creamos el xades:DigestMethod
        		Element metodoResumenElemento = doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + DIGEST_METHOD);

        		// Creamos los atributos de DigestMethod
        		Attr propiedadesAlgoritmoFirmado = doc.createAttribute(ALGORITHM);
        		propiedadesAlgoritmoFirmado.setValue(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1);
        		NamedNodeMap atributosMetodoResumenElemento = metodoResumenElemento.getAttributes();
        		atributosMetodoResumenElemento.setNamedItem(propiedadesAlgoritmoFirmado);

        		// Creamos el xades:DigestValue
        		// El mensaje de la respuesta es el OCSPResponse
        		String digestCertificado =CADENA_VACIA;
        		try
        		{
        			MessageDigest resumenCertificadoTemp = MessageDigest.getInstance(SHA_1);
        			byte[] resumenMensajeByte = resumenCertificadoTemp.digest(mensajeRespuesta);
        			digestCertificado = new String(Base64Coder.encode(resumenMensajeByte));
        		}
        		catch (NoSuchAlgorithmException nsae)
        		{
        			throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_20));
        		}

        		Element valorResumenElemento = doc.createElementNS(SCHEMA_DSIG, xmldsigNS + DOS_PUNTOS + DIGEST_VALUE);

        		valorResumenElemento.appendChild(doc.createTextNode(digestCertificado));

        		valorYResumenElemento.appendChild(metodoResumenElemento);
        		valorYResumenElemento.appendChild(valorResumenElemento);

        		elementOCSPRef.appendChild(identificadorElementoOCSP);
        		elementOCSPRef.appendChild(valorYResumenElemento);

        		elementOCSPRefs.appendChild(elementOCSPRef);
        	}
        }
        
        elementoPrincipal.appendChild(certificadosElementosFirma);
        elementoPrincipal.appendChild(revocacionesElementoFirma);

        return doc;
    }

    /**
     * Este metodo añade la implementación del sello de tiempo de tipo 1 (implícito) para 
     * XADES-X según los esquemas 1.2.2 y 1.3.2.
     * Los elementos sobre los que se calcula el sello son los siguientes:
	 * 		- SignatureValue
	 * 		- SignatureTimestamp
	 * 		- CompleteCertificateRefs
	 * 		- CompleteRevocationRefs
	 * 	Opcionalmente en el esquema 1.2.2 y 1.3.2:
	 * 		- AttributeCertificateRefs
	 * 		- AttributeRevocationRefs
	 * 
     * @param Element UnsignedSignatureProperties Nodo a partir del cual se añade el nodo SigAndRefsTimeStamp
     * @return Documento de firma con formato XADES-X
     * @throws AddXadesException En caso de error
     */
    private Document addXadesX(Element UnsignedSignatureProperties)
    	throws AddXadesException
    	{
    	// Se obtiene el documento que contiene al nodo UnsignedSignatureProperties
    	Document doc = UnsignedSignatureProperties.getOwnerDocument();
    	
    	// Se obtiene el nodo Signature que contiene al nodo UnsignedSignatureProperties (es el 4º padre, según esquema XAdES)
    	Node padre = UnsignedSignatureProperties.getParentNode();
    	for (int i = 0; i < 3; ++i) {
    		if (padre != null)
    			padre = padre.getParentNode();
    		else
    			// No se encuentra el nodo Signature
    			throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_33) + ESPACIO +
        				SIGNATURE);
    	}
    	
    	Element signatureElement = null;
    	if (padre != null && SIGNATURE.equals(padre.getLocalName()))
    		signatureElement = (Element)padre;
    	else
    		// No se encuentra el nodo Signature
    		throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_33) + ESPACIO +
    				SIGNATURE);
    	 
    	// Se crea el nodo SigAndRefsTimeStamp
        Element SigAndRefsTimeStampElement =
        	doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + SIG_AND_REFS_TIME_STAMP);
        
        // Se coloca el nodo creado al final del nodo UnsignedSignatureProperties
        UnsignedSignatureProperties.appendChild(SigAndRefsTimeStampElement);
        
        // Se obtiene el listado de elementos de un sello de tiempo XAdES X
        ArrayList<Element> elementosSelloX = null;
        try {
			elementosSelloX = UtilidadXadesX.obtenerListadoXADESX1imp(xadesSchema, signatureElement, SigAndRefsTimeStampElement);
		} catch (BadFormedSignatureException e) {
			throw new AddXadesException(e.getMessage(), e);
		} catch (FirmaXMLError e) {
			throw new AddXadesException(e.getMessage(), e);
		}
		
		// Se añaden nodos de referencia a los nodos obtenidos para el cálculo del sello (sólo para esquema 1.2.2)
		if (SCHEMA_XADES_122.equals(xadesSchema)) {
			// Se obtienen las Ids de los nodos del sello de tiempo X
			ArrayList<String> elementosIdSelloX = UtilidadTratarNodo.obtenerIDs(elementosSelloX);
			
			// Se crea una estructura con los nodos Include que contienen las URIs que apuntan a estas IDs
			ArrayList<Element> nodosInclude = new ArrayList<Element> (elementosIdSelloX.size());
			Iterator<String> itIds = elementosIdSelloX.iterator();
			while (itIds.hasNext()) {
				String Id = itIds.next();
				Element includeNode = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + INCLUDE);
	        	Attr includeNodeUri = doc.createAttribute(URI);
	        	includeNodeUri.setValue(ALMOHADILLA + Id);
	        	NamedNodeMap atributosNodo = includeNode.getAttributes();
	        	atributosNodo.setNamedItem(includeNodeUri);
	        	
	        	nodosInclude.add(includeNode);
			}
			
	        // Se escribe en el nodo SigAndRefsTimeStamp el listado obtenido por orden
			Iterator<Element> itIncludes = nodosInclude.iterator();
			while (itIncludes.hasNext()) {
				Element includeNode = itIncludes.next();			
				SigAndRefsTimeStampElement.appendChild(includeNode);
			}
		}
		
		// Se obtiene el Array de bytes de los nodos obtenidos
		byte[] byteData = null;
		try {
			byteData = UtilidadTratarNodo.obtenerByte(elementosSelloX);
		} catch (FirmaXMLError e) {
			throw new AddXadesException(e.getMessage(), e);
		}
		
		// Calculamos el hash del sello de tiempo y lo escribimos en el nodo como String del array de bytes calculado
		TSCliente tsCli = null;
        if(estadoProxy) {
			System.setProperty("http.proxyHost", servidorProxy);
			System.setProperty("http.proxyPort", Integer.toString(numeroPuertoProxy));
			if (isProxyAuth) {
				Authenticator.setDefault(new SimpleAuthenticator(proxyUser, proxyPass));
			} 
			else {
				Authenticator.setDefault(null);
			}
        }
        tsCli = new TSCliente(servidorTSA,algoritmoTSA);
        
        try {
			byteData = tsCli.generarSelloTiempo(byteData);
		} catch (TSClienteError e) {
			throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_11) + e.getMessage()) ;
		}
		String hashSelloX = new String(Base64Coder.encode(byteData));
		
		// Escribimos el resultado en el nodo EncapsulatedTimeStamp
		Element encapsulatedTimeStampNode = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + ENCAPSULATED_TIME_STAMP);
		encapsulatedTimeStampNode.appendChild(doc.createTextNode(hashSelloX));	
		SigAndRefsTimeStampElement.appendChild(encapsulatedTimeStampNode);

        return doc;
    }

    /**
     * Este metodo añade la implementación del sello de tiempo de tipo 2 (explícito) para 
     * XADES-X según los esquemas 1.2.2 y 1.3.2.
     * Los elementos sobre los que se calcula el sello son los siguientes:
	 * 		- CompleteCertificateRefs
	 * 		- CompleteRevocationRefs
	 * 	Opcionalmente en el esquema 1.2.2 y 1.3.2:
	 * 		- AttributeCertificateRefs
	 * 		- AttributeRevocationRefs
	 * 
     * @param Element UnsignedSignatureProperties Nodo a partir del cual se añade el nodo SigAndRefsTimeStamp
     * @return Documento de firma con formato XADES-X
     * @throws AddXadesException En caso de error
     */
    private Document addXadesX2(Element UnsignedSignatureProperties)
    	throws AddXadesException
    	{
    	// Se obtiene el documento que contiene al nodo UnsignedSignatureProperties
    	Document doc = UnsignedSignatureProperties.getOwnerDocument();
    	
    	// Se obtiene el nodo Signature que contiene al nodo UnsignedSignatureProperties (es el 4º padre, según esquema XAdES)
    	Node padre = UnsignedSignatureProperties.getParentNode();
    	for (int i = 0; i < 3; ++i) {
    		if (padre != null)
    			padre = padre.getParentNode();
    		else
    			// No se encuentra el nodo Signature
    			throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_33) + ESPACIO +
        				SIGNATURE);
    	}
    	
    	Element signatureElement = null;
    	if (padre != null && SIGNATURE.equals(padre.getLocalName()))
    		signatureElement = (Element)padre;
    	else
    		// No se encuentra el nodo Signature
    		throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_33) + ESPACIO +
    				SIGNATURE);
    	 
    	// Se crea el nodo RefsOnlyTimeStamp
        Element RefsOnlyTimeStampElement =
        	doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + REFS_ONLY_TIME_STAMP);
        
        // Se coloca el nodo creado al final del nodo UnsignedSignatureProperties
        UnsignedSignatureProperties.appendChild(RefsOnlyTimeStampElement);
        
        // Se obtiene el listado de elementos de un sello de tiempo de tipo 2 XAdES X
        ArrayList<Element> elementosSelloX2 = null;
        try {
			elementosSelloX2 = UtilidadXadesX.obtenerListadoXADESX2exp(xadesSchema, signatureElement, RefsOnlyTimeStampElement);
		} catch (BadFormedSignatureException e) {
			throw new AddXadesException(e.getMessage(), e);
		} catch (FirmaXMLError e) {
			throw new AddXadesException(e.getMessage(), e);
		}
		
		// Se añaden nodos de referencia a los nodos obtenidos para el cálculo del sello (sólo para esquema 1.2.2)
		if (SCHEMA_XADES_122.equals(xadesSchema)) {
			// Se obtienen las Ids de los nodos del sello de tiempo X de tipo 2
			ArrayList<String> elementosIdSelloX2 = UtilidadTratarNodo.obtenerIDs(elementosSelloX2);
			
			// Se crea una estructura con los nodos Include que contienen las URIs que apuntan a estas IDs
			ArrayList<Element> nodosInclude = new ArrayList<Element> (elementosIdSelloX2.size());
			Iterator<String> itIds = elementosIdSelloX2.iterator();
			while (itIds.hasNext()) {
				String Id = itIds.next();
				Element includeNode = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + INCLUDE);
	        	Attr includeNodeUri = doc.createAttribute(URI);
	        	includeNodeUri.setValue(ALMOHADILLA + Id);
	        	NamedNodeMap atributosNodo = includeNode.getAttributes();
	        	atributosNodo.setNamedItem(includeNodeUri);
	        	
	        	nodosInclude.add(includeNode);
			}
			
	        // Se escribe en el nodo SigAndRefsTimeStamp el listado obtenido por orden
			Iterator<Element> itIncludes = nodosInclude.iterator();
			while (itIncludes.hasNext()) {
				Element includeNode = itIncludes.next();			
				RefsOnlyTimeStampElement.appendChild(includeNode);
			}
		}
		
		// Se obtiene el Array de bytes de los nodos obtenidos
		byte[] byteData = null;
		try {
			byteData = UtilidadTratarNodo.obtenerByte(elementosSelloX2);
		} catch (FirmaXMLError e) {
			throw new AddXadesException(e.getMessage(), e);
		}
		
		// Calculamos el hash del sello de tiempo y lo escribimos en el nodo como String del array de bytes calculado
		TSCliente tsCli = null;
        if(estadoProxy) {
			System.setProperty("http.proxyHost", servidorProxy);
			System.setProperty("http.proxyPort", Integer.toString(numeroPuertoProxy));
			if (isProxyAuth) {
				Authenticator.setDefault(new SimpleAuthenticator(proxyUser, proxyPass));
			} 
			else {
				Authenticator.setDefault(null);
			}
        }
        tsCli = new TSCliente(servidorTSA,algoritmoTSA);
        
        try {
			byteData = tsCli.generarSelloTiempo(byteData);
		} catch (TSClienteError e) {
			throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_11) + e.getMessage()) ;
		}
		String hashSelloX = new String(Base64Coder.encode(byteData));
		
		// Escribimos el resultado en el nodo EncapsulatedTimeStamp
		Element encapsulatedTimeStampNode = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + ENCAPSULATED_TIME_STAMP);
		encapsulatedTimeStampNode.appendChild(doc.createTextNode(hashSelloX));	
		RefsOnlyTimeStampElement.appendChild(encapsulatedTimeStampNode);

        return doc;
    }
    
    /**
     * Este metodo añade la implementacion para XADES-XL
     * 
     * @param doc Documento de firma con formato XADES-X
     * @param respuestas Cadena de certificación junto a sus respuestas OCSP del certificado de firma
     * @return Documento de firma con formato XADES-XL
     * @throws AddXadesException En caso de error
     */
    private Document addXadesXL(Document doc, ArrayList<RespYCerts> respuestas)
    	throws AddXadesException
    	{
    	// Recogemos el nodo UnsignedSignatureProperties del cual dependen los nodos
    	// que hay que añadir para completar la firma XADES-XL
        Element elementoPrincipal = null ;

        NodeList nodos = doc.getElementsByTagNameNS(xadesSchema, UNSIGNED_SIGNATURE_PROPERTIES);
        
        
        if(nodos.getLength() != 0)
        {
            elementoPrincipal = (Element)nodos.item(0);
        }
        else
        {
            throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_19));
        }

        // Se añaden los certificados referenciados en el nodo CertificateValues
        if(respuestas != null)
        {
	        Element valorCertificadoElemento =
	            doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + CERTIFICATE_VALUES);
	        Iterator<RespYCerts> itResp = respuestas.iterator();
	        boolean hasNext = itResp.hasNext();
	        while (hasNext) {
        		RespYCerts resp = itResp.next();
        		hasNext = itResp.hasNext();
	        	X509Certificate certificado = resp.getX509Cert();

	        	Element elementoCertificadoEncapsulado = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + ENCAPSULATED_X_509_CERTIFICATE);

		        try {
					elementoCertificadoEncapsulado.appendChild(
					        doc.createTextNode(new String(Base64Coder.encode(certificado.getEncoded()))));
					String id = resp.getIdCertificado();
					if ((id != null) && (!CADENA_VACIA.equals(id.trim())))
						elementoCertificadoEncapsulado.setAttribute(ID, id);
				} catch (CertificateEncodingException e) {
					log.error(e);
					throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_23));
				} catch (DOMException e) {
					log.error(e);				
					throw new AddXadesException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_23));
        		}

		        valorCertificadoElemento.appendChild(elementoCertificadoEncapsulado);
	        }

        	elementoPrincipal.appendChild(valorCertificadoElemento);

            // Se añade la respuesta del servidor OCSP
            Element valoresElementosRevocados =
                doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + REVOCATION_VALUES);


            Element valorElementOCSP =
                doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + OCSP_VALUES);

	        itResp = respuestas.iterator();
	        hasNext = itResp.hasNext();
	        while (hasNext) {
        		RespYCerts resp = itResp.next();
        		hasNext = itResp.hasNext();
	            Element valorElementoEncapsuladoOCSP = doc.createElementNS(xadesSchema, xadesNS + DOS_PUNTOS + ENCAPSULATED_OCSP_VALUE);
	            valorElementoEncapsuladoOCSP.appendChild(
	                    doc.createTextNode(new String(Base64Coder.encode(resp.getRespOCSP()))));
	            valorElementoEncapsuladoOCSP.setAttribute(ID, resp.getIdOCSP());
	            valorElementOCSP.appendChild(valorElementoEncapsuladoOCSP);
	        }

            valoresElementosRevocados.appendChild(valorElementOCSP);

            elementoPrincipal.appendChild(valoresElementosRevocados);
        }

        return doc;
    }
    
    /**
     * Este método se encarga de insertar las URIs de XADES-C en la firma
     * 
     * @param doc, Documento con la firma xml
     * @param listaArchivos, Lista de nombres de la respuestaOCSP y el path de certificación
     * @return Document doc, Documento firmado con las nuevas URI´s
     */
    public Document addURIXadesC(Document doc, ArrayList<NombreFicheros> listaArchivos)
    {
    	
    	NodeList completeCertificateRefs = null;
    	NodeList completeRevocationRefs = null;
    	
    	completeCertificateRefs = doc.getElementsByTagNameNS(xadesSchema, COMPLETE_CERTIFICATE_REFS);
    	completeRevocationRefs = doc.getElementsByTagNameNS(xadesSchema, COMPLETE_REVOCATION_REFS);
    	
    	if (completeCertificateRefs.getLength() == 0 || completeRevocationRefs.getLength() == 0) {
    		log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_29));
    		return doc;
    	}
    	
    	// A continuación se sacan las referencias OCSP del nodo OCSPRefs
    	Node ocspRefs = (Node)completeRevocationRefs.item(0).getFirstChild();
        	
    	// Si ha encontrado el nodo OCSPRefs, se pasa a capturar su contenido
        if (ocspRefs != null)
        {
        	// Se saca la lista de referencias
        	NodeList refs = ocspRefs.getChildNodes();
        	int l = refs.getLength();
        	for (int i=0; i<l; i++)
           	{
        		// Sacamos los nodos OCSPRef uno por uno
           		Element ocspRef = (Element)refs.item(i); // Sacamos OCSPRef
           		NodeList list = ocspRef.getElementsByTagNameNS(xadesSchema, OCSP_IDENTIFIER);
           		// Si existe, incluimos la URI de su respuesta OCSP
           		if (ocspRef != null) {
           			Attr uri = doc.createAttribute(URI);
    				uri.setValue((listaArchivos.get(i)).getNameFileOCSPResp());

    				NamedNodeMap nodoOCSP = list.item(0).getAttributes();
    				nodoOCSP.setNamedItem(uri);
           		}
           	}        	
        }
    	
    	// A continuación se sacan los Certificados del nodo CertRefs
    	Node certRefs = (Node)completeCertificateRefs.item(0).getFirstChild();

    	// Si ha encontrado el nodo CertRefs, se pasa a capturar su contenido
    	if (certRefs != null)
    	{
    		// Se saca la lista de certificados
    		NodeList certs = certRefs.getChildNodes();
    		int l = certs.getLength();
    		
    		if (l!=(listaArchivos.size()-1)) {
    			log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_30));
    		}

    		for (int i=0; i<l; i++) 
    		{
    			// Sacamos los nodos Cert uno por uno
    			Node certificado = certs.item(i); // Sacamos cert
    			if (certificado != null) {
    				// incluimos la uri

    				Attr uri = doc.createAttribute(URI);
    				uri.setValue(listaArchivos.get(i+1).getNameFileX509Cert()); // La posicion 0 es del certificado firmante

    				NamedNodeMap nodoCertificado = certificado.getAttributes();
    				nodoCertificado.setNamedItem(uri);
           		}
           	}
        }
    	        
        return doc;
    }
    
    /**
     * Este método se encarga de guardar los archivos OCSP
     * @param respuesta Cadena de certificación junto a sus respuestas OCSP del certificado de firma
     * @param rutaFicheroFirmado Path donde se almacena la firma generada, para incluir los archivos de respuesta OCSP
     * @param nomFichero Nombre del fichero firmado para asociar los ficheros de las respuestas OCSP con él
     * @return un ArrayList con la lista de archivos guardados
     */
    public ArrayList<NombreFicheros> saveOCSPFiles(ArrayList<RespYCerts> respuesta, String rutaFicheroFirmado, String nomFichero)
    {
    	OutputStream f = null;
    	File directorio = null;
    	NombreFicheros nameFiles = null;
    	ArrayList<NombreFicheros> listaArchivos = new ArrayList<NombreFicheros>();
    	nomFichero = nomFichero.substring(0,nomFichero.indexOf(PUNTO));
    	String pathDir = rutaFicheroFirmado + DIR_OCSP;
    	
    	if (respuesta != null) {
    		
    		int longitud = respuesta.size();
    		for (int x = 0; x < longitud; ++x) { // Se incluyen todas las OCSPResp y todos los Cert del path menos el firmante
    			
    			RespYCerts respAndCert = respuesta.get(x);
    			nameFiles = new NombreFicheros();
    			
    			// Guardamos la respuesta OCSP
    			ByteArrayInputStream respuestaOCSP = new ByteArrayInputStream(respAndCert.getRespOCSP());
				// AppPerfect: Falsos positivos. No son expresiones constantes
    			String nomRespOCSP = DIR_OCSP + FICH_OCSP_RESP + nomFichero + GUION + (x + 1) + EXTENSION_OCS;
				log.debug(I18n.getResource(LIBRERIAXADES_FIRMAXML_DEBUG_6) + ESPACIO + rutaFicheroFirmado + nomRespOCSP);
    			try {
    				directorio = new File(pathDir);
    				directorio.mkdir();
    				f = new FileOutputStream(rutaFicheroFirmado + nomRespOCSP);
    				int ch = respuestaOCSP.read();
    				ByteArrayOutputStream bos = new ByteArrayOutputStream();
    				while ((ch) >= 0) {
    					bos.write(ch);
    					ch = respuestaOCSP.read();
    				}
    				f.write(bos.toByteArray());
    			} catch (FileNotFoundException e) {
    				log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_27) + ESPACIO + e.getMessage());
    			} catch (IOException e) {
    				log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_27) + ESPACIO + e.getMessage());
    			} finally {
    				try {
    					f.flush() ;
    					f.close() ;
    					nameFiles.setNameFileOCSPResp(nomRespOCSP);
    				} catch (IOException e) {
    					log.error(e.getMessage());
    				}
    			}
    		
    			if (x!=0) // Se salta el certificado que firma 
    			{ 
    				// Guardamos la cadena de certificados
    				X509Certificate certificado = respAndCert.getX509Cert();
    				String nomCert = DIR_CERTS + FICH_CERT_REF + nomFichero + GUION + (x) + EXTENSION_CER;
    				log.debug(I18n.getResource(LIBRERIAXADES_FIRMAXML_DEBUG_5) + ESPACIO + rutaFicheroFirmado + nomCert);
    				try {
    					directorio = new File(rutaFicheroFirmado + DIR_CERTS);
        				directorio.mkdir();
    					f = new BufferedOutputStream(new FileOutputStream(rutaFicheroFirmado + nomCert));
    					f.write(certificado.getEncoded()) ; // CertRef guardado
    				} catch (FileNotFoundException e) {
    					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_26) + ESPACIO + e.getMessage());
    				} catch (IOException e) {
    					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_26) + ESPACIO + e.getMessage());
    				} catch (CertificateEncodingException e) {
    					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_26) + ESPACIO + e.getMessage());
					} finally {
    					try {
    						f.flush() ;
    						//AppPerfect: Falso positivo
    						f.close() ;
    						nameFiles.setNameFileX509Cert(nomCert);
    					} catch (IOException e) {
    						log.error(e.getMessage());
    					}
    				}
    			} else {
    				nameFiles.setNameFileX509Cert(CADENA_VACIA);
    			}
    			listaArchivos.add(nameFiles);
    		}
    		
    	} else {
    		log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_27));
    		return null;
    	}
    	
    	return listaArchivos;
    }
}
