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
 * Copyright 2007 Ministerio de Industria, Turismo y Comercio
 * 
 */

package es.mityc.firmaJava.ejemplos.xades;

/**
 * Clase de ejemplo para la generación de una firma digital XAdES
 * utilizando la librería XADES
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class EjemploXADESFirma {
	
//	private Vector<X509Certificate> listCertificates = null;
//	private X509Certificate certificadoParaFirmar = null;
//	final private static String NOMBRE_FICHERO_A_FIRMAR = "FicheroAFirmar.xml";
//	final private static String NOMBRE_FICHERO_FIRMADO = "FicheroFirmado.xml";
//	
//	public static void main(String[] args) {
//		EjemploXADESFirma p = new EjemploXADESFirma();
//		p.firmaXADES();
//	}
//
//	@SuppressWarnings("unchecked")
//	private void firmaXADES() {
//		// Accedemos al almacén de certificados de Mozilla Firefox
//		InterfazFirma si = UtilidadFirmaElectronica.getSignatureInstance(EnumAlmacenCertificados.ALMACEN_MOZILLA);
//		try {
//			listCertificates = si.getAllCertificates("/home/borillo/.mozilla/firefox/zhy933al.default");
//		} catch (FirmaXMLError e1) {
//			// TODO Auto-generated catch block
//			e1.printStackTrace();
//		}
//
//		System.out.println("Hay " + listCertificates.size() + " certificados");
//		mostrarInformacionCertificados(listCertificates);
//		//recogemos el certificado para firmar
//		if ( listCertificates.size() != 0){
//			//Seleccionamos el primero de los certificados para firmar
//			certificadoParaFirmar = (X509Certificate) listCertificates.get(0);
//			try {
//				finalizarFirma();
//			} catch (Exception e) {
//				e.printStackTrace();
//			}
//		} else {
//			System.err.println("No hay ningún certificado disponible");   
//		}
//	}
//	
//	private void finalizarFirma() throws Exception {
//		
//		// Instanciamos la estructura de datos que almacenará el resultado de la firma
//		byte[] resultadoFirma = null;
//		
//		// Instanciamos la clase Configuracion de Libreriaconfiguracion 
//		Configuracion configuracion = new Configuracion();
//		// Cargamos el valor de los parámetros contenidos en el fichero SignXML.properties
//		configuracion.cargarConfiguracion();
//
//		// Validacion OCSP. Es usual chequear, previo a la firma, que el certificado es válido.
//		// Se realiza la validación OCSP del certificado, sin proxy
//		/*
//		RespuestaOCSP respuesta = new RespuestaOCSP();
//		try {
//			String ocspServer = "http://ocsp.ctpa.mityc.es:80";
//		    es.mityc.firmaJava.ocsp.OCSPCliente ocspCliente = new OCSPCliente(ocspServer);
//		    respuesta = ocspCliente.validateCert(cert);
//		} catch (OCSPClienteError ex) {
//			System.err.println("El certificado no ha superado la validación OCSP");
//			ex.printStackTrace();
//		} catch (Exception ex) {
//		  System.err.println("Error en la validación OCSP");
//			ex.printStackTrace();
//		}
//		
//		if (respuesta.getNroRespuesta() != es.mityc.firmaJava.ocsp.OCSPCliente.GOOD) {
//			System.err.println("El certificado no ha superado la validación OCSP");
//			return;
//		}
//		 */
//		//Fin Validacion OCSP
//	
//		// Se lee el fichero a firmar
//		String rutaFicheroAFirmar = System.getProperty("user.dir") + "/" + NOMBRE_FICHERO_A_FIRMAR;
//		BufferedReader in = new BufferedReader(new InputStreamReader(new FileInputStream(rutaFicheroAFirmar), "UTF-8"));
//		
//		// Atención!!! aquí cambiamos los saltos de carro del fichero original para facilitar la lectura del ejemplo
//		// Si se ha de firmar exactamente el mismo fichero de entrada la lectura no ha de modificar el resultado.
//		StringBuffer xmlToSign = new StringBuffer();
//		while (in.ready()) {
//			xmlToSign.append(in.readLine());
//		}
//		
//		// Nodos que contendrán las firmas del fichero (se incluye Certificate1 porque será donde irá el certificado de firma)
//		String nodesToSign = "Certificate1,fichero";
//		configuracion.setValor("xmlNodeToSign", nodesToSign);
//
//        // Para firmar con un certificado del almacén de Internet Explorer
////        InterfazObjetoDeFirma soi = UtilidadFirmaElectronica.getSignatureObject(EnumAlmacenCertificados.ALMACEN_EXPLORER, 
////        		certificadoParaFirmar, 
////        		"",
////        		configuracion);
//        
//        // Para firmar con un certificado del almacén de Mozilla
//        InterfazObjetoDeFirma soi = UtilidadFirmaElectronica.getSignatureObject(EnumAlmacenCertificados.ALMACEN_MOZILLA, 
//        		certificadoParaFirmar, 
//        		"/home/borillo/.mozilla/firefox/zhy933al.default",
//        		configuracion);
//        
//        // Se prepara e inicializa el interfaz de firma
//        try {
//			soi.initSign();
//		} catch (ClienteError e1) {
//			e1.printStackTrace();
//		}
//
//        // Se realiza la firma
//		try {
//			resultadoFirma = soi.sign(xmlToSign.toString());
//		} catch (ClienteError e) {
//			e.printStackTrace();
//		}
//
//		if (resultadoFirma != null) {
//			System.out.println("\n\nLa firma se creo correctamente. Se salva con el nombre " + NOMBRE_FICHERO_FIRMADO);
//
//			// Una vez finalizada la firma, escribimos el resultado en el fichero de salida
//			grabarAFichero(resultadoFirma);
//
//			// Si se quiere continuar realizando validaciones o firmas es necesario inicializar esta estructura
//			ParametrosFirmaXML.initialize();
//		} else
//			System.out.println("\n\nLa firma NO se creo correctamente");
//	}
//
//	/**
//	 * Método que guarda a fichero un array de bytes
//	 * @param firmaXADESByte
//	 */
//	private void grabarAFichero(byte[] firmaXADESByte) {
//
//		FileOutputStream fos = null;
//		try {
//			String rutaFicheroFirmado = System.getProperty("user.dir") + "/" + NOMBRE_FICHERO_FIRMADO;
//			fos = new FileOutputStream(rutaFicheroFirmado);
//			fos.write(firmaXADESByte);
//		} catch (FileNotFoundException e) {
//			e.printStackTrace();
//		} catch (IOException e) {
//			e.printStackTrace();
//		} finally {
//			try {
//				fos.flush();
//				fos.close();
//			} catch (IOException e) {
//				e.printStackTrace();
//			}			
//		}
//	}
//
//	/**
//	 * Método que muestra por consola la informacion sobre los certificados pasados
//	 * @param listCertificates
//	 */
//	private void mostrarInformacionCertificados(Vector<X509Certificate> listCertificates) {
//
//		for (int a = 0; a < listCertificates.size(); a++) {
//			X509Certificate certTemp = (X509Certificate) listCertificates.get(a);
//
//			System.out.println("-----------------------------");
//			//Emitido para
//			System.out.println("Subject --> "
//					+ UtilidadDNIe.getCN(certTemp, UtilidadDNIe.SUBJECT_OR_ISSUER.SUBJECT));
//
//			//Emitido por
//			System.out.println("Issuer -->"
//					+ UtilidadDNIe.getCN(certTemp, UtilidadDNIe.SUBJECT_OR_ISSUER.ISSUER));
//
//			//Fecha de emisión y de caducidad
//			SimpleDateFormat formateador = new SimpleDateFormat("dd/MM/yyyy");
//			String emision = formateador.format(certTemp.getNotBefore());
//			System.out.println("Not Before -->" + emision);
//			String caducidad = formateador.format(certTemp.getNotAfter());
//			System.out.println("Not After -->" + caducidad);
//
//			/*Usos permitidos del certificado
//			  Recogemos el keyUsage
//
//				KeyUsage ::= BIT STRING {
//					     digitalSignature        (0),
//					     nonRepudiation          (1),
//					     keyEncipherment         (2),
//					     dataEncipherment        (3),
//					     keyAgreement            (4),
//					     keyCertSign             (5),
//					     cRLSign                 (6),
//					     encipherOnly            (7),
//					     decipherOnly            (8) }
//
//			 Usos del certificado: 
//			 F Firma digital,N no repudio, Cc cifrado de claves, 
//			 Cd cifrado de datos, Ac Acuerdo de claves, Fc Firma de certificados, 
//			 Fcrl Firma de CRL, Sc Solo cifrado, Sf solo firma
//
//			 */
//			
//			String claveUsoString = "";
//			String[] claveUsoArray = { "F", "N", "Cc", "Cd", "Ac", "Fc",
//					"Fcrl", "Sc", "Sf" };
//			boolean[] claveUso = certTemp.getKeyUsage();
//			if (claveUso != null) {
//				for (int z = 0; z < claveUso.length; z++) {
//					if (claveUso[z]) {
//						claveUsoString = claveUsoString + claveUsoArray[z] + ",";
//					}
//				}
//			} else {
//				claveUsoString = "No definido ";
//			}
//			System.out.println("Key Usage -->"
//					+ claveUsoString.substring(0, claveUsoString.length() - 1));
//			System.out.println("-----------------------------");
//		}
//	}
}