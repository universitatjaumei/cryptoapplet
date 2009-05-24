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

package es.mityc.firmaJava.libreria;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public interface ConstantesXADES {
	static final String ESPACIO = " ";
    static final String I18N = "i18n";
    static final String DOLAR = "$";
    static final String ALMOHADILLA = "#";
    
    static final String NUEVA_LINEA = "\n";
    static final String CADENA_VACIA = "";
    
    static final String CLIENTE_VALCERT1_TEXT2 = "cliente.valcert1.text2";
    
    static final String MSG_NUMERO_FIRMAS_DOCUMENTO = "Número de firmas en el documento: ";
    
    static final String ERR_CN_NO_TIPO_STRING = "El valor del nombre obtenido del certificado no es de tipo String";
    static final String ERR_CERT_NO_VALUES = "El certificado no contiene valores";
    
    static final String JAVAPLUGIN_VERSION = "javaplugin.version";
    static final String OS_NAME = "os.name";
    static final String JAVA_TMP_DIR = "java.io.tmpdir";
    static final String LINUX = "linux";
    static final String WIN = "win";
    static final String OS_VERSION = "os.version";
    
    static final String USER_HOME = "user.home";
    static final String USER_NAME = "user.name";
    static final String USER_DIR  = "user.dir";
    static final String FILE_SEPARATOR = "file.separator";
    static final String TMP_DIR = "tmp.dir";
    static final String PKCS12 = "PKCS12";
    
    static final String CERTIFICATE_POLICIES_OID = "2.5.29.32";
    
    static final String UTF8DECODER_ERROR = "UTF8Decoder does not handle 32-bit characters";
    
    static final String BROWSER = "browser";
    static final String OPERA = "Opera";
    static final String LIBRERIAXADES_UTILIDADFIRMAELECTRONCIA_ERROR1 = "libreriaxades.utilidadfirmaelectronica.error1";
    static final String SUN_PLUGIN = "sun.plugin";
    static final String NETSCAPE = "netscape";
    static final String IEXPLORER = "iexplorer";    
	
    static final String BACK_SLASH = "\\";
    
    static final String POLICY_OID_CERTIFICADO_AUTENTICACION_DNIE = "2.16.724.1.2.2.2.4";
    
    static final String CN_IGUAL = "CN=";
    static final String COMA = ",";
    static final String PUNTO = ".";
    static final String COMILLAS = "\"";
    
    static final String NUMERO_DE_SERIE = "Número de serie";
    static final String IGUAL = "=";
    static final String OID_2_5_4_5 = "OID.2.5.4.5";
    static final String SERIAL_NUMBER = "serialNumber";
    
    static final String OU_DNIE = "OU=DNIE";
    static final String O_DIRECCION_GENERAL_DE_LA_POLICIA = "O=DIRECCION GENERAL DE LA POLICIA";

    static final String DEFAULT_LOCALE	= "es";
	static final String LOCALE_FILES	= "i18n_libreriaXADES";
	
	static final String LOCALE	= "locale";
	
	static final String LIBRERIAXADES_GETPKCS12KEYS_TEXTO_1	= "libreriaxades.getpkcs12keys.texto1";
	static final String LIBRERIAXADES_GETPKCS12KEYS_TEXTO_2	= "libreriaxades.getpkcs12keys.texto2";
	static final String LIBRERIAXADES_GETPKCS12KEYS_TEXTO_3	= "libreriaxades.getpkcs12keys.texto3";
	
	static final String PARTS	= "parts";
	static final String GUION	= "-";
	static final String GUION_TEMPORAL	= "-temporal";
	
	static final String LINE_DOS_PUNTOS	= "Line: ";
	static final String URI_DOS_PUNTOS	= "URI: ";
	
	static final String LIBRERIA_UTILIDADES_ANALIZADOR_ERROR_1	= "libreriaxades.utilidades.analizador.error1";
	static final String LIBRERIA_UTILIDADES_ANALIZADOR_ERROR_2	= "libreriaxades.utilidades.analizador.error2";
	static final String LIBRERIA_UTILIDADES_ANALIZADOR_ERROR_3	= "libreriaxades.utilidades.analizador.error3";
	
	static final String TARJETAS_PROPERTIES = "Tarjetas.properties";
	
	static final String CARACTERES_VALIDOS = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789_";
	static final String MASK = "******************************************************************************************";
	
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_1 = "libreriaxades.validatarjeta.texto1";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_2 = "libreriaxades.validatarjeta.texto2";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_3 = "libreriaxades.validatarjeta.texto3";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_4 = "libreriaxades.validatarjeta.texto4";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_5 = "libreriaxades.validatarjeta.texto5";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_6 = "libreriaxades.validatarjeta.texto6";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_7 = "libreriaxades.validatarjeta.texto7";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_8 = "libreriaxades.validatarjeta.texto8";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_9 = "libreriaxades.validatarjeta.texto9";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_10 = "libreriaxades.validatarjeta.texto10";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_11 = "libreriaxades.validatarjeta.texto11";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_12 = "libreriaxades.validatarjeta.texto12";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_13 = "libreriaxades.validatarjeta.texto13";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_14 = "libreriaxades.validatarjeta.texto14";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_15 = "libreriaxades.validatarjeta.texto15";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_16 = "libreriaxades.validatarjeta.texto16";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_17 = "libreriaxades.validatarjeta.texto17";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_18 = "libreriaxades.validatarjeta.texto18";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_19 = "libreriaxades.validatarjeta.texto19";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_20 = "libreriaxades.validatarjeta.texto20";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_21= "libreriaxades.validatarjeta.texto21";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_22 = "libreriaxades.validatarjeta.texto22";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_23 = "libreriaxades.validatarjeta.texto23";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_24 = "libreriaxades.validatarjeta.texto24";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_25 = "libreriaxades.validatarjeta.texto25";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_26 = "libreriaxades.validatarjeta.texto26";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_27 = "libreriaxades.validatarjeta.texto27";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_28 = "libreriaxades.validatarjeta.texto28";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_29 = "libreriaxades.validatarjeta.texto29";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_30 = "libreriaxades.validatarjeta.text30";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_31 = "libreriaxades.validatarjeta.texto31";
	static final String LIBRERIAXADES_VALIDARTARJETA_TEXTO_32 = "libreriaxades.validatarjeta.texto32";

	static final String COLLECTION = "Collection"; 
	static final String BC = "BC";
	static final String SUNPCKS11_TOKEN = "SunPKCS11-Token";
	
	static final String NAME_IGUAL_TOKEN = "name = Token ";
	static final String LIBRARY_IGUAL = "library = ";
	
	static final String PKCS11 = "PKCS11";
	
	static final String MOZILLA = "Mozilla";
	
	static final String LIBRERIAXADES_FIRMAMOZILLA_DEBUG_1 = "libreriaxades.firmamozilla.debug1";
	static final String LIBRERIAXADES_FIRMAMOZILLA_DEBUG_2 = "libreriaxades.firmamozilla.debug2";
	static final String LIBRERIAXADES_FIRMAMOZILLA_DEBUG_3 = "libreriaxades.firmamozilla.debug3";
	static final String LIBRERIAXADES_FIRMAMOZILLA_DEBUG_4 = "libreriaxades.firmamozilla.debug4";
	
	static final String X_509 = "X.509";
	
	static final String USER_DOS_PUNTOS = "User: ";
	static final String ISSUER_DOS_PUNTOS = "Issuer: ";
	static final String SN_DOS_PUNTOS = "SN: ";
	static final String SEPARACION = "<-->";
	
	static final String LIBRERIAXADES_FIRMAMOZILLA_INFO_1 = "libreriaxades.firmamozilla.info1";
	static final String LIBRERIAXADES_FIRMAMOZILLA_INFO_2 = "libreriaxades.firmamozilla.info2";
	static final String LIBRERIAXADES_FIRMAMOZILLA_INFO_3 = "libreriaxades.firmamozilla.info3";
	static final String LIBRERIAXADES_FIRMAMOZILLA_INFO_4 = "libreriaxades.firmamozilla.info4";
	static final String LIBRERIAXADES_FIRMAMOZILLA_INFO_5 = "libreriaxades.firmamozilla.info5";
	static final String LIBRERIAXADES_FIRMAMOZILLA_INFO_6 = "libreriaxades.firmamozilla.info6";
	static final String LIBRERIAXADES_FIRMAMOZILLA_INFO_7 = "libreriaxades.firmamozilla.info7";
	static final String LIBRERIAXADES_FIRMAMOZILLA_INFO_8 = "libreriaxades.firmamozilla.info8";
	
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_1 = "libreriaxades.firmamozilla.error1";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_2 = "libreriaxades.firmamozilla.error2";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_3 = "libreriaxades.firmamozilla.error3";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_4 = "libreriaxades.firmamozilla.error4";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_5 = "libreriaxades.firmamozilla.error5";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_6 = "libreriaxades.firmamozilla.error6";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_7 = "libreriaxades.firmamozilla.error7";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_8 = "libreriaxades.firmamozilla.error8";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_9 = "libreriaxades.firmamozilla.error9";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_10 = "libreriaxades.firmamozilla.error10";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_11 = "libreriaxades.firmamozilla.error11";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_12 = "libreriaxades.firmamozilla.error12";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_13 = "libreriaxades.firmamozilla.error13";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_14 = "libreriaxades.firmamozilla.error14";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_15 = "libreriaxades.firmamozilla.error15";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_16 = "libreriaxades.firmamozilla.error16";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_17 = "libreriaxades.firmamozilla.error17";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_18 = "libreriaxades.firmamozilla.error18";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_19 = "libreriaxades.firmamozilla.error19";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_20 = "libreriaxades.firmamozilla.error20";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_21 = "libreriaxades.firmamozilla.error21";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_22 = "libreriaxades.firmamozilla.error22";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_23 = "libreriaxades.firmamozilla.error23";
	static final String LIBRERIAXADES_FIRMAMOZILLA_ERROR_24 = "libreriaxades.firmamozilla.error24";

	static final String SLASH = "/"	;
	static final String APPDATA = "AppData";
	static final String MOZILLA_FIREFOX_PROFILES_INI = "/Mozilla/Firefox/profiles.ini";
	static final String NAME_DEFAULT = "Name=default";
	static final String CERO = "0";
	
	static final String MITYC_PROVIDER = "MitycProvider";
	static final String MITYC_PROVIDER_V_1_0_IMPLEMENTACION = "MitycProvider v1.0, implementación de SHA1withRSA basado en KeyStore de Microsoft y OpenOCES - OpenSign";
	static final String SIGNATURE_SHA1_WITH_RSA = "Signature.SHA1withRSA";
	static final String ES_MITYC_FIRMAJAVA_LIBRERIA_MICROSOFT_FIRMAMS = "es.mityc.firmaJava.libreria.microsoft.FirmaMSBridge";
	
	
	
	static final String algoritmoCifrado = "SHA1withRSA";
	
	static final String LIBRERIAXADES_FIRMAMS_ERROR_11 = "libreriaxades.firmams.error11";
	
	static final String DLL_FIRMA_VC_DLL = "DLLFirmaVC.dll";
	static final String COMA_ESPACIO = ", ";
	
	static final String LIBRERIAXADES_FIRMAMS_ERROR_1 = "libreriaxades.firmams.error1";
	static final String LIBRERIAXADES_FIRMAMS_ERROR_2 = "libreriaxades.firmams.error2";
	static final String LIBRERIAXADES_FIRMAMS_ERROR_3 = "libreriaxades.firmams.error3";
	static final String LIBRERIAXADES_FIRMAMS_ERROR_4 = "libreriaxades.firmams.error4";
	static final String LIBRERIAXADES_FIRMAMS_ERROR_12 = "libreriaxades.firmams.error12";
	static final String LIBRERIAXADES_FIRMAMS_ERROR_8 = "libreriaxades.firmams.error8";
	static final String LIBRERIAXADES_FIRMAMS_ERROR_9 = "libreriaxades.firmams.error9";
	static final String LIBRERIAXADES_FIRMAMS_ERROR_13 = "libreriaxades.firmams.error13";
	static final String LIBRERIAXADES_FIRMAMS_ERROR_14 = "libreriaxades.firmams.error14";
	static final String LIBRERIAXADES_FIRMAMS_ERROR_15 = "libreriaxades.firmams.error15";
	static final String LIBRERIAXADES_FIRMAMS_ERROR_16 = "libreriaxades.firmams.error16";
	
	static final String ENGINE_GET_PARAMETER = "engineGetParameter ";
	static final String MY = "My";
	static final String DLL_ALMACEN_MS = "BridgeCSPJNI.dll";
	static final String DLL_ALMACEN_MOZILLA = "jss3.dll,libnspr4.dll,libplc4.dll,libplds4.dll,nss3.dll,smime3.dll,softokn3.dll,ssl3.dll";
	static final String FICH_CERT_REF = "/CertRef-";
	static final String EXTENSION_CER = ".cer";
	static final String FICH_OCSP_RESP = "/RespuestaOCSP-";
	static final String EXTENSION_OCS = ".ocs";
	
	static final String LIBRERIAXADES_FIRMAMS_INFO_1 = "libreriaxades.firmams.info1";
	static final String LIBRERIAXADES_FIRMAMS_INFO_2 = "libreriaxades.firmams.info2";
	static final String LIBRERIAXADES_FIRMAMS_INFO_3 = "libreriaxades.firmams.info3";
	static final String LIBRERIAXADES_FIRMAMS_INFO_4 = "libreriaxades.firmams.info4";
	
	static final String LIBRERIAXADES_FIRMAMS_DEBUG_1 = "libreriaxades.firmams.debug1";
	
	static final String YES_MAYUSCULA = "Y";
	static final String SI_MAYUSCULA = "S";
	
	static final String LITERAL_EMPTY = "empty";

    static final String LIBRERIAXADES_SIGNATUREBASERSA_DSA = "Created SignatureDSA using ";


    static final String LIBRERIAXADES_NOSUCHALGORITHM = "algorithms.NoSuchAlgorithm";

    static final String LIBRERIAXADES_WRONGKEY = "algorithms.WrongKeyForThisOperation";

    static final String LIBRERIAXADES_HMAC_LENGTH = "algorithms.HMACOutputLengthOnlyForHMAC";

    static final String LIBRERIAXADES_NOALGORITHMONRSA = "algorithms.CannotUseAlgorithmParameterSpecOnRSA";
    

    static final String XML_XADES_NS =  "xmlXadesNS";
    static final String XML_NS = "xmlns";
    static final String VALIDAR_XADES_SCHEMA = "validarXadesSchema";
    static final String IS_SELLO_X_TIPO_1 = "isSelloXTipo1";
    static final String LITERAL_CLASE_T = "Clase T";
    static final String LITERAL_CLASE_X_TIPO_1 = "Clase X Tipo 1";
    static final String LITERAL_CLASE_X_TIPO_2 = "Clase X Tipo 2";
    static final String LITERAL_CLASE_A = "Clase A";
    static final String IS_PROXY = "isProxy";
    static final String PROXY_SERVER_URL = "proxyServerURL";
    static final String PROXY_PORT_NUMBER = "proxyPortNumber";
    static final String IS_PROXY_AUTH = "isProxyAuth";
    static final String PROXY_USER = "proxyUser";
    static final String PROXY_PASS = "proxyPass";
    static final String LIBRERIAXADES_FIRMAMSL_WARN_1 = "libreriaxades.firmaxml.warn1";
    static final String TIME_STAMP_SERVER_URL = "timeStampServerURL";
    static final String TIME_STAMP_HASH_ALG = "timeStampHashAlg";
    static final String SIGNATURE_NODE_ID = "signatureNodeId";
    static final String SIGNED_INFO_NODE_ID = "signedInfoNodeId";
    static final String SIGNATURE = "Signature";
     
    static final String XADES_SCHEMA = "xadesSchema" ;
    
    static final String GUION_SIGNED_PROPERTIES = "-SignedProperties";
    static final String SIGNED_PROPERTIES_ID = "SignedPropertiesID";    
    static final String SIGNED_PROPERTIES = "SignedProperties";
    
    
    static final String CERTIFICATE1 = "Certificate1";
    static final String MENOR_ROOT_MAYOR = "<root>";
    static final String JAVA_HEAP_SPACE = "Java heap space";
    static final String FIRMA_NO_CONTIENE_DATOS = "La firma no contiene datos";
    static final String SELLO_TIEMPO = "SelloTiempo";    
    
//    static final String XADES_T =     "Xades-T";
    static final String ID = "Id";
    static final String ID_MINUS = "id";
    static final String ID_MAYUS = "ID";
    static final String RSA = "RSA";
    static final String OCSP_SERVER_URL = "OCSPserverURL";    
    static final String M = "M";
    static final String XML_NODE_TO_SIGN = "xmlNodeToSign";
    static final String SIGNATURE_VALUE = "SignatureValue";
    static final String ENCODING_XML = "encodingXML";
    static final String VALIDATE_ROOT_NODE = "validateRootNode" ;
    
    static final String LIBRERIAXADES_FIRMAXML_DEBUG_1 = "libreriaxades.firmaxml.debug1";
    static final String LIBRERIAXADES_FIRMAXML_DEBUG_2 = "libreriaxades.firmaxml.debug2";
	static final String LIBRERIAXADES_FIRMAXML_DEBUG_3 = "libreriaxades.firmaxml.debug3";
	static final String LIBRERIAXADES_FIRMAXML_DEBUG_4 = "libreriaxades.firmaxml.debug4";
	static final String LIBRERIAXADES_FIRMAXML_DEBUG_5 = "libreriaxades.firmaxml.debug5";
	static final String LIBRERIAXADES_FIRMAXML_DEBUG_6 = "libreriaxades.firmaxml.debug6";       
    
	static final String LIBRERIAXADES_FIRMAXML_ERROR_1 ="libreriaxades.firmaxml.error1";      
	static final String LIBRERIAXADES_FIRMAXML_ERROR_2 ="libreriaxades.firmaxml.error2";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_3 ="libreriaxades.firmaxml.error3";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_4 ="libreriaxades.firmaxml.error4";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_5 ="libreriaxades.firmaxml.error5";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_6 ="libreriaxades.firmaxml.error6";      
	static final String LIBRERIAXADES_FIRMAXML_ERROR_7 ="libreriaxades.firmaxml.error7";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_8 ="libreriaxades.firmaxml.error8";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_9 ="libreriaxades.firmaxml.error9";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_10 ="libreriaxades.firmaxml.error10";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_11 ="libreriaxades.firmaxml.error11";      
	static final String LIBRERIAXADES_FIRMAXML_ERROR_12 ="libreriaxades.firmaxml.error12";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_13 ="libreriaxades.firmaxml.error13";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_14 ="libreriaxades.firmaxml.error14";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_15 ="libreriaxades.firmaxml.error15";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_16 ="libreriaxades.firmaxml.error16";      
	static final String LIBRERIAXADES_FIRMAXML_ERROR_17 ="libreriaxades.firmaxml.error17";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_18 ="libreriaxades.firmaxml.error18";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_19 ="libreriaxades.firmaxml.error19";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_20 ="libreriaxades.firmaxml.error20";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_21 ="libreriaxades.firmaxml.error21";      
	static final String LIBRERIAXADES_FIRMAXML_ERROR_22 ="libreriaxades.firmaxml.error22";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_23 ="libreriaxades.firmaxml.error23";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_24 ="libreriaxades.firmaxml.error24";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_25 ="libreriaxades.firmaxml.error25";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_26 ="libreriaxades.firmaxml.error26";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_27 ="libreriaxades.firmaxml.error27";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_28 ="libreriaxades.firmaxml.error28";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_29 ="libreriaxades.firmaxml.error29";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_30 ="libreriaxades.firmaxml.error30";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_31 ="libreriaxades.firmaxml.error31";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_32 ="libreriaxades.firmaxml.error32";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_33 ="libreriaxades.firmaxml.error33";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_34 ="libreriaxades.firmaxml.error34";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_35 ="libreriaxades.firmaxml.error35";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_36 ="libreriaxades.firmaxml.error36";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_37 ="libreriaxades.firmaxml.error37";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_38 ="libreriaxades.firmaxml.error38";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_39 ="libreriaxades.firmaxml.error39";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_40 ="libreriaxades.firmaxml.error40";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_41 ="libreriaxades.firmaxml.error41";
	static final String LIBRERIAXADES_FIRMAXML_ERROR_42 ="libreriaxades.firmaxml.error41";
	static final String LIBRERIAXADES_VALIDARXADES = "validarXadesSchema";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR1 = "libreriaxades.validarfirmaxml.error1";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR2 = "libreriaxades.validarfirmaxml.error2";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR3 = "libreriaxades.validarfirmaxml.error3";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR4 = "libreriaxades.validarfirmaxml.error4";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR5 = "libreriaxades.validarfirmaxml.error5";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR6 = "libreriaxades.validarfirmaxml.error6";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR7 = "libreriaxades.validarfirmaxml.error7";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR8 = "libreriaxades.validarfirmaxml.error8";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR9 = "libreriaxades.validarfirmaxml.error9";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR10 = "libreriaxades.validarfirmaxml.error10";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR11 = "libreriaxades.validarfirmaxml.error11";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR12 = "libreriaxades.validarfirmaxml.error12";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR13 = "libreriaxades.validarfirmaxml.error13";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR14 = "libreriaxades.validarfirmaxml.error14";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR15 = "libreriaxades.validarfirmaxml.error15";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR16 = "libreriaxades.validarfirmaxml.error16";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR17 = "libreriaxades.validarfirmaxml.error17"; 
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR18 = "libreriaxades.validarfirmaxml.error18";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR19 = "libreriaxades.validarfirmaxml.error19";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR20 = "libreriaxades.validarfirmaxml.error20";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR21 = "libreriaxades.validarfirmaxml.error21";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR22 = "libreriaxades.validarfirmaxml.error22";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR23 = "libreriaxades.validarfirmaxml.error23";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR24 = "libreriaxades.validarfirmaxml.error24";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR25 = "libreriaxades.validarfirmaxml.error25";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR26 = "libreriaxades.validarfirmaxml.error26";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR27 = "libreriaxades.validarfirmaxml.error27";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR28 = "libreriaxades.validarfirmaxml.error28";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR29 = "libreriaxades.validarfirmaxml.error29";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR30 = "libreriaxades.validarfirmaxml.error30";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR31 = "libreriaxades.validarfirmaxml.error31";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR32 = "libreriaxades.validarfirmaxml.error32";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR33 = "libreriaxades.validarfirmaxml.error33";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR34 = "libreriaxades.validarfirmaxml.error34";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR35 = "libreriaxades.validarfirmaxml.error35";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR36 = "libreriaxades.validarfirmaxml.error36";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR37 = "libreriaxades.validarfirmaxml.error37";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR38 = "libreriaxades.validarfirmaxml.error38";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR39 = "libreriaxades.validarfirmaxml.error39";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR40 = "libreriaxades.validarfirmaxml.error40";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR41 = "libreriaxades.validarfirmaxml.error41";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR42 = "libreriaxades.validarfirmaxml.error42";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR43 = "libreriaxades.validarfirmaxml.error43";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR44 = "libreriaxades.validarfirmaxml.error44";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR45 = "libreriaxades.validarfirmaxml.error45";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR46 = "libreriaxades.validarfirmaxml.error46";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR47 = "libreriaxades.validarfirmaxml.error47";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR48 = "libreriaxades.validarfirmaxml.error48";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR49 = "libreriaxades.validarfirmaxml.error49";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR50 = "libreriaxades.validarfirmaxml.error50";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR51 = "libreriaxades.validarfirmaxml.error51";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR52 = "libreriaxades.validarfirmaxml.error52";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR53 = "libreriaxades.validarfirmaxml.error53";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR54 = "libreriaxades.validarfirmaxml.error54";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR55 = "libreriaxades.validarfirmaxml.error55";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR56 = "libreriaxades.validarfirmaxml.error56";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR57 = "libreriaxades.validarfirmaxml.error57";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR58 = "libreriaxades.validarfirmaxml.error58";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR59 = "libreriaxades.validarfirmaxml.error59";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR60 = "libreriaxades.validarfirmaxml.error60";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR61 = "libreriaxades.validarfirmaxml.error61";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR62 = "libreriaxades.validarfirmaxml.error62";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR63 = "libreriaxades.validarfirmaxml.error63";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR64 = "libreriaxades.validarfirmaxml.error64";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR65 = "libreriaxades.validarfirmaxml.error65";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR66 = "libreriaxades.validarfirmaxml.error66";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR67 = "libreriaxades.validarfirmaxml.error67";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR68 = "libreriaxades.validarfirmaxml.error68";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR69 = "libreriaxades.validarfirmaxml.error69";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR70 = "libreriaxades.validarfirmaxml.error70";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR71 = "libreriaxades.validarfirmaxml.error71";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR72 = "libreriaxades.validarfirmaxml.error72";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR73 = "libreriaxades.validarfirmaxml.error73";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR74 = "libreriaxades.validarfirmaxml.error74";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR75 = "libreriaxades.validarfirmaxml.error75";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR76 = "libreriaxades.validarfirmaxml.error76";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR77 = "libreriaxades.validarfirmaxml.error77";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR78 = "libreriaxades.validarfirmaxml.error78";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR79 = "libreriaxades.validarfirmaxml.error79";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR80 = "libreriaxades.validarfirmaxml.error80";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR81 = "libreriaxades.validarfirmaxml.error81";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR82 = "libreriaxades.validarfirmaxml.error82";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR83 = "libreriaxades.validarfirmaxml.error83";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR84 = "libreriaxades.validarfirmaxml.error84";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR85 = "libreriaxades.validarfirmaxml.error85";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR86 = "libreriaxades.validarfirmaxml.error86";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR87 = "libreriaxades.validarfirmaxml.error87";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR88 = "libreriaxades.validarfirmaxml.error88";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR89 = "libreriaxades.validarfirmaxml.error89";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR90 = "libreriaxades.validarfirmaxml.error90";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR91 = "libreriaxades.validarfirmaxml.error91";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR92 = "libreriaxades.validarfirmaxml.error92";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR93 = "libreriaxades.validarfirmaxml.error93";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR94 = "libreriaxades.validarfirmaxml.error94";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR95 = "libreriaxades.validarfirmaxml.error95";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR96 = "libreriaxades.validarfirmaxml.error96";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR97 = "libreriaxades.validarfirmaxml.error97";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR98 = "libreriaxades.validarfirmaxml.error98";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR99 = "libreriaxades.validarfirmaxml.error99";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR100 = "libreriaxades.validarfirmaxml.error100";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR101 = "libreriaxades.validarfirmaxml.error101";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR102	= "libreriaxades.validarfirmaxml.error102";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR103	= "libreriaxades.validarfirmaxml.error103";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR104	= "libreriaxades.validarfirmaxml.error104";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR105	= "libreriaxades.validarfirmaxml.error105";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR106	= "libreriaxades.validarfirmaxml.error106";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR107	= "libreriaxades.validarfirmaxml.error107";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR108	= "libreriaxades.validarfirmaxml.error108";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR109	= "libreriaxades.validarfirmaxml.error109";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR110	= "libreriaxades.validarfirmaxml.error110";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR111	= "libreriaxades.validarfirmaxml.error111";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR112	= "libreriaxades.validarfirmaxml.error112";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR113	= "libreriaxades.validarfirmaxml.error113";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR114	= "libreriaxades.validarfirmaxml.error114";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR115	= "libreriaxades.validarfirmaxml.error115";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR116	= "libreriaxades.validarfirmaxml.error116";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR117	= "libreriaxades.validarfirmaxml.error117";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR118	= "libreriaxades.validarfirmaxml.error118";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR119	= "libreriaxades.validarfirmaxml.error119";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR120	= "libreriaxades.validarfirmaxml.error120";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR121	= "libreriaxades.validarfirmaxml.error121";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR122	= "libreriaxades.validarfirmaxml.error122";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR123	= "libreriaxades.validarfirmaxml.error123";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR124	= "libreriaxades.validarfirmaxml.error124";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR125	= "libreriaxades.validarfirmaxml.error125";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR126	= "libreriaxades.validarfirmaxml.error126";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR127	= "libreriaxades.validarfirmaxml.error127";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR128	= "libreriaxades.validarfirmaxml.error128";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR129	= "libreriaxades.validarfirmaxml.error129";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR130	= "libreriaxades.validarfirmaxml.error130";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR131	= "libreriaxades.validarfirmaxml.error131";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR132	= "libreriaxades.validarfirmaxml.error132";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR133	= "libreriaxades.validarfirmaxml.error133";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR134	= "libreriaxades.validarfirmaxml.error134";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR135	= "libreriaxades.validarfirmaxml.error135";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR136	= "libreriaxades.validarfirmaxml.error136";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR137	= "libreriaxades.validarfirmaxml.error137";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR138	= "libreriaxades.validarfirmaxml.error138";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR139	= "libreriaxades.validarfirmaxml.error139";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR140	= "libreriaxades.validarfirmaxml.error140";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR141	= "libreriaxades.validarfirmaxml.error141";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR142	= "libreriaxades.validarfirmaxml.error142";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR143	= "libreriaxades.validarfirmaxml.error143";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR144	= "libreriaxades.validarfirmaxml.error144";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR145	= "libreriaxades.validarfirmaxml.error145";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR146	= "libreriaxades.validarfirmaxml.error146";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR147	= "libreriaxades.validarfirmaxml.error147";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR148	= "libreriaxades.validarfirmaxml.error148";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR149	= "libreriaxades.validarfirmaxml.error149";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR150	= "libreriaxades.validarfirmaxml.error150";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR151	= "libreriaxades.validarfirmaxml.error151";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR152	= "libreriaxades.validarfirmaxml.error152";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR153	= "libreriaxades.validarfirmaxml.error153";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR154	= "libreriaxades.validarfirmaxml.error154";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR155	= "libreriaxades.validarfirmaxml.error155";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR156	= "libreriaxades.validarfirmaxml.error156";
	static final String LIBRERIAXADES_VALIDARFIRMA_ERROR157	= "libreriaxades.validarfirmaxml.error157";
	
	static final String LIBRERIAXADES_VALIDARFIRMA_INFO1 = "libreriaxades.validarfirmaxml.info1";
	static final String LIBRERIAXADES_VALIDARFIRMA_INFO2 = "libreriaxades.validarfirmaxml.info2";
	static final String LIBRERIAXADES_VALIDARFIRMA_WARN1 = "libreriaxades.firmaxml.warn1";
	
	static final String LIBRERIAXADES_VALIDARFIRMA_TEXTO1 = "libreriaxades.validarfirmaxml.texto1";
	static final String LIBRERIAXADES_VALIDARFIRMA_TEXTO2 = "libreriaxades.validarfirmaxml.texto2";
	static final String LIBRERIAXADES_VALIDARFIRMA_TEXTO3 = "libreriaxades.validarfirmaxml.texto3";
	static final String LIBRERIAXADES_VALIDARFIRMA_TEXTO4 = "libreriaxades.validarfirmaxml.texto4";
	static final String LIBRERIAXADES_VALIDARFIRMA_TEXTO5 = "libreriaxades.validarfirmaxml.texto5";
	static final String LIBRERIAXADES_VALIDARFIRMA_TEXTO6 = "libreriaxades.validarfirmaxml.texto6";
	static final String LIBRERIAXADES_VALIDARFIRMA_TEXTO7 = "libreriaxades.validarfirmaxml.texto7";

//	static final String LIBRERIAXADES_BES = "XADES-BES";
//	static final String LIBRERIAXADES_T = "XADES-T";
//	static final String LIBRERIAXADES_C = "XADES-C";
//	static final String LIBRERIAXADES_XL = "XADES-XL";
	static final String LIBRERIAXADES_SIGNATURE = "Signature";
	static final String LIBRERIAXADES_SIGNATUREVALUE = "SignatureValue";
	static final String LIBRERIAXADES_SIGNINGTIME = "SigningTime";
	static final String LIBRERIAXADES_CLAIMEDROLE = "ClaimedRole";
	static final String LIBRERIAXADES_SIGNATURETIMESTAMP = "SignatureTimeStamp";
	static final String LIBRERIAXADES_SIGNINGCERTIFICATE = "SigningCertificate";
	static final String LIBRERIAXADES_QUALIFYING_PROPERTIES = "QualifyingProperties";
	static final String LIBRERIAXADES_COMPLETECERTIFICATEREFS = "CompleteCertificateRefs";
	static final String LIBRERIAXADES_COMPLETEREVOCATIONREFS = "CompleteRevocationRefs";
	static final String ATTRIBUTE_CERTIFICATE_REFS = "AttributeCertificateRefs";
	static final String ATTRIBUTE_REVOCATION_REFS = "AttributeRevocationRefs";
	static final String LIBRERIAXADES_CRLREFS = "CRLRefs";
	static final String LIBRERIAXADES_CRLREF = "CRLRef";
	static final String LIBRERIAXADES_CRLIDENTIFIER = "CRLIdentifier";
	static final String LIBRERIAXADES_KEY_INFO = "KeyInfo";
	static final String LIBRERIAXADES_X509_DATA = "X509Data";
	static final String LIBRERIAXADES_X509_CERTIFICATE = "X509Certificate";
	static final String LIBRERIAXADES_ISSUER = "Issuer";
	static final String LIBRERIAXADES_ISSUERTIME = "IssueTime";
	static final String LIBRERIAXADES_NUMBER = "Number";
	static final String LIBRERIAXADES_SHA1 = "SHA-1";
	static final String LIBRERIAXADES_CERTREFS = "CertRefs";
	static final String LIBRERIAXADES_CERTDIGEST = "CertDigest";
	static final String LIBRERIAXADES_CERT_PATH = "CertPath";
	static final String LIBRERIAXADES_X_509_ISSUER_NAME = "X509IssuerName";        
	static final String LIBRERIAXADES_X_509_SERIAL_NUMBER = "X509SerialNumber";
	static final String LIBRERIAXADES_X509_SERIAL_ISSUER = "X509IssuerSerial";
	static final String LIBRERIAXADES_PRIMER = "primer ";
	static final String LIBRERIAXADES_DIGESTALGVALUE = "DigestAlgAndValue";
	static final String LIBRERIAXADES_DIGEST_METHOD = "DigestMethod";
	static final String LIBRERIAXADES_DIGESTVALUE = "DigestValue";
	static final String LIBRERIAXADES_ISSUER_SERIAL = "IssuerSerial";
	static final String LIBRERIAXADES_OCSP_IDENTIFIER = "OCSPIdentifier";
	static final String LIBRERIAXADES_RESPONDER_ID = "ResponderID";
	static final String LIBRERIAXADES_PRODUCED_AT = "ProducedAt";
	static final String LIBRERIAXADES_ENCTIMESTAMP = "EncapsulatedTimeStamp";
	static final String LIBRERIAXADES_CRLVALUE = "EncapsulatedCRLValue";
	static final String LIBRERIAXADES_OCSPVALUE = "EncapsulatedOCSPValue";
	static final String LIBRERIAXADES_X509VALUE = "EncapsulatedX509Certificate";
	static final String LIBRERIAXADES_ISPROXY = "isProxy";
	static final String LIBRERIAXADES_ISPROXYAUTH = "isProxyAuth";
	static final String LIBRERIAXADES_PROXYURL = "proxyServerURL";
	static final String LIBRERIAXADES_PROXYPORT = "proxyPortNumber";
	static final String LIBRERIAXADES_PROXYUSER = "proxyUser";
	static final String LIBRERIAXADES_PROXYPASS = "proxyPass";
	static final String LIBRERIAXADES_ADD_EPES = "addEPES";
	static final String LIBRERIAXADES_EPES_POLICY_MANAGER = "EPESPolicyManager";
	static final String LIBRERIAXADES_IMPLIEDPOLICY_MANAGER = "implied";
	static final String LIBRERIAXADES_IMPLIEDPOLICY	= "ImpliedPolicy";

	static final String PROCESO_FIRMA = "procesofirma";
	static final String PUNTO_TMP = ".tmp";
	static final String COUNTER_SIGNATURE = "CounterSignature";

	static final String SIGNED_SIGNATURE_PROPERTIES = "SignedSignatureProperties";
	static final String SIGNING_TIME = "SigningTime";
	    
	static final String DIGEST_METHOD = "DigestMethod";        
	static final String CERT_DIGEST = "CertDigest";        
	static final String SIGNING_CERTIFICATE = "SigningCertificate";        
	static final String CERT = "Cert";

	static final String UNSIGNED_SIGNATURE_PROPERTIES = "UnsignedSignatureProperties";

	static final String CERTIFICATE = "Certificate";
	static final String QUALIFYING_PROPERTIES = "QualifyingProperties";
	static final String TARGET = "Target";
	
	static final String QUALIFIER =  "Qualifier";        
	static final String TRANSFORM = "Transform";
	static final String TRANSFORMS = "Transforms";
	static final String ALGORITHM =  "Algorithm";        
	static final String SHA_1 = "SHA-1";    
	static final String UTF8 = "UTF-8";
	static final String DIGEST_VALUE = "DigestValue";        
	static final String ISSUER_SERIAL = "IssuerSerial";        
	static final String X_509_ISSUER_NAME = "X509IssuerName";        
	static final String X_509_SERIAL_NUMBER = "X509SerialNumber";        
	static final String SIGNATURE_POLICY_IDENTIFIER = "SignaturePolicyIdentifier";        
	static final String SIGNATURE_POLICY_ID = "SignaturePolicyId";
	static final String SIGNATURE_POLICY_IMPLIED = "SignaturePolicyImplied";   
	static final String SIG_POLICY_ID = "SigPolicyId";
	static final String IDENTIFIER = "Identifier";
	static final String DESCRIPTION = "Description";
	static final String SIG_POLICY_HASH = "SigPolicyHash";
	static final String SIGNER_ROLES = "SignerRoles";        
	static final String SIGNER_ROLE = "SignerRole";        
	static final String CLAIMED_ROLES = "ClaimedRoles";        
	static final String CLAIMED_ROLE = "ClaimedRole";        
	static final String OBJECT = "Object";        
	static final String GUION_OBJECT = "-Object";    
	    
	static final String UNSIGNED_PROPERTIES = "UnsignedProperties";        
	static final String GUION_UNSIGNED_PROPERTIES = "-UnsignedProperties";          
	static final String SIGNATURE_TIME_STAMP = "SignatureTimeStamp";
	static final String INCLUDE = "Include"; 
	static final String URI = "URI";      
	static final String TYPE = "Type";
	static final String REFERENCE = "Reference";
	static final String ALMOHADILLA_SIGNATURE_VALUE = "#SignatureValue";        
	static final String CANONICALIZATION_METHOD = "CanonicalizationMethod";        
	static final String URL_CANONICALIZATION = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";        
	static final String ENCAPSULATED_TIME_STAMP = "EncapsulatedTimeStamp";        

	static final String COMPLETE_CERTIFICATE_REFS = "CompleteCertificateRefs";
	static final String CERT_REFS = "CertRefs";
	static final String OCSP_REFS = "OCSPRefs";
	static final String CRL_REFS = "CRLRefs";
	static final String OCSP = "OCSP";
	static final String OCSP_REF = "OCSPRef";
	static final String OCSP_IDENTIFIER = "OCSPIdentifier";
	static final String RESPONDER_ID = "ResponderID";
	static final String CORCHETE_1_CORCHETE = "[1]";
	static final String BY_NAME = "ByName";
	static final String BY_KEY = "ByKey";
	static final String PRODUCE_AT = "ProducedAt";
	static final String DIGEST_ALG_AND_VALUE = "DigestAlgAndValue";
	static final String SIG_AND_REFS_TIME_STAMP = "SigAndRefsTimeStamp";
	static final String REFS_ONLY_TIME_STAMP = "RefsOnlyTimeStamp";
	static final String ENCODING = "Encoding";
	static final String OCSP_VALUES = "OCSPValues";
	static final String CRL_VALUES = "CRLValues";
	static final String ENCAPSULATED_OCSP_VALUE = "EncapsulatedOCSPValue";
	static final String ENCAPSULATED_CRL_VALUE = "EncapsulatedCRLValue";
	static final String REVOCATION_VALUES = "RevocationValues";
	static final String CERTIFICATE_VALUES = "CertificateValues";
	static final String ENCAPSULATED_X_509_CERTIFICATE = "EncapsulatedX509Certificate";
	static final String COMPLETE_REVOCATION_REFS = "CompleteRevocationRefs";
	static final String ARCHIVE_TIME_STAMP = "ArchiveTimeStamp";
	
	static final String Z_FECHA = "Z";
	static final String MILIS_FECHA = "+0000";
	
	static final String SCHEMA_XADES_111 = "http://uri.etsi.org/01903/v1.1.1#";
	static final String SCHEMA_XADES_122 = "http://uri.etsi.org/01903/v1.2.2#";
	static final String SCHEMA_XADES_132 = "http://uri.etsi.org/01903/v1.3.2#";
	static final String SCHEMA_XADES = "http://uri.etsi.org/01903#";
	static final String SCHEMA_DSIG = "http://www.w3.org/2000/09/xmldsig#";
	
	static final String PROVIDER_DOS_PUNTOS = "Provider:";
	
	static final String CRL_NUMBER_OID = "2.5.29.20"; 
	
	static final String ES_MAYUSCULA = "ES";
	static final String ES_MINUSCULA = "es";
	
    /** No options specified. Value is zero. */
    public final static int NO_OPTIONS = 0;
    
    /** Specify encoding. */
    public final static int ENCODE = 1;
    
    
    /** Specify decoding. */
    public final static int DECODE = 0;
    
    
    /** Specify that data should be gzip-compressed. */
    public final static int GZIP = 2;
    
    
    /** Don't break lines when encoding (violates strict Base64 specification) */
    public final static int DONT_BREAK_LINES = 8;
	
	/** 
	 * Encode using Base64-like encoding that is URL- and Filename-safe as described
	 * in Section 4 of RFC3548: 
	 * <a href="http://www.faqs.org/rfcs/rfc3548.html">http://www.faqs.org/rfcs/rfc3548.html</a>.
	 * It is important to note that data encoded this way is <em>not</em> officially valid Base64, 
	 * or at the very least should not be called Base64 without also specifying that is
	 * was encoded using the URL- and Filename-safe dialect.
	 */
	 public final static int URL_SAFE = 16;
	 
	 
	 /**
	  * Encode using the special "ordered" dialect of Base64 described here:
	  * <a href="http://www.faqs.org/qa/rfcc-1940.html">http://www.faqs.org/qa/rfcc-1940.html</a>.
	  */
	 public final static int ORDERED = 32;
	 
	 static final String DOS_PUNTOS_ESPACIO = ": ";
	 static final String DOS_PUNTOS = ":";
	 
	 static final String STR_USAGE_JAVA_BASE_64 = "Usage: java Base64 -e|-d inputfile outputfile";
	 static final String STR_BAD_BASE_64 = "Bad Base64 input character at ";
	 static final String STR_DECIMAL = "(decimal)";
	 static final String STR_FILE_TOO_BIG = "File is too big for this convenience method (";
	 static final String STR_BYTES = " bytes).";
	 static final String STR_ERROR_DECODING = "Error decoding from file ";
	 static final String STR_ERROR_ENCODING ="Error encoding from file ";
	 static final String STR_US_ASCII = "US-ASCII";
	 static final String STR_ERROR_IN_BASE_64 = "Error in Base64 code reading stream.";
	 static final String STR_INVALID_CHARACTER = "Invalid character in Base64 data.";
	 static final String STR_INPUT_NOT_PROPERLY_PADDED = "Base64 input not properly padded." ;
	 
	 static final String STR_IMPROPERLY_PADDED = "Improperly padded Base64 input.";
	 
	 static final String STR_LENGTH_OF_BASE_64 = "Length of Base64 encoded input string is not a multiple of 4.";
	 static final String STR_ILLEGAL_CHARACTER_IN_BASE_64 = "Illegal character in Base64 encoded data.";

	 // Constantes para la policy
	 static final String LIBRERIAXADES_POLICY_SIGNATUREPOLICYID = "SignaturePolicyId";
	 static final String LIBRERIAXADES_POLICY_SIGPOLICYID = "SigPolicyId";
	 static final String LIBRERIAXADES_POLICY_IDENTIFIER = "Identifier";
	 static final String LIBRERIAXADES_POLICY_SIGPOLICYHASH = "SigPolicyHash";
	 static final String LIBRERIAXADES_POLICY_SIGNATUREPOLICYIDENTIFIER = "SignaturePolicyIdentifier";
	 static final String LIBRERIAXADES_POLICY_SIGNATUREPOLICYIMPLIED = "SignaturePolicyImplied";

	 static final String CONFIG_POLICY_IDENTIFIER = "PolicyId";
	 static final String CONFIG_POLICY_HASH_SHA1 = "PolicyHashSHA1";
	 static final String CONFIG_POLICY_HASH_SHA256 = "PolicyHashSHA256";
	 
	 // Constantes PoliciesManager	 
	 static final String CIERRA_PARENTESIS = ")";
	 static final String LIBRERIAXADES_POLICY_MANAGER_NO_FILE = "No hay fichero de configuración de policies";
	 static final String LIBRERIAXADES_POLICY_MANAGER_NO_INSTANCIA = "La clase asociada no se puede instanciar (";
	 static final String LIBRERIAXADES_POLICY_MANAGER_NO_PERMISOS = "No hay permisos para instanciar el validador (";
	 static final String LIBRERIAXADES_POLICY_MANAGER_NO_CLAVE = "La clase asociada al valor no se encuentra disponible (";
	 static final String LIBRERIAXADES_POLICY_MANAGER_NO_TIPO = "La clase asociada no es del tipo validador (";
	 static final String LIBRERIAXADES_POLICY_MANAGER_NO_VALIDADOR = "No hay validador de policy asociado a esa clave: ";

}


