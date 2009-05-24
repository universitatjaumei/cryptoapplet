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

package es.mityc.firmaJava.ts;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertStoreException;
import java.text.SimpleDateFormat;

import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.InputStreamRequestEntity;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.GenTimeAccuracy;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

/**
 * Clase encargada de generar y validar los sellos de tiempo
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class TSCliente implements ConstantesTSA{
    
	/**
	 * Servidor que da el servicio de sellado de tiempo
	 */
    private String servidorTSA;
    /**
     * Algoritmo hash del sello de tiempo
     */
    private String algoritmoHash;
        
   	private static final HttpClient cliente = new HttpClient(); 
   	
   	private static final Integer INT5000 = new Integer(5000);
    
   static Log log = LogFactory.getLog(TSCliente.class.getName());
    

    
    /**
     * Crea una nueva instancia de TSCliente
     * @param nombreServidor Nombre del servidor
     * @param algoritmoHash Algoritmo del hash del Sello de Tiempo
     */
    public TSCliente(String nombreServidor, String algoritmoHash) 
    {
        super();
   	 	this.servidorTSA = nombreServidor;        
	     
	     // Algoritmo para digest aceptado por defecto
	     this.algoritmoHash = TSPAlgoritmos.SHA1;
	     
	     // Comprueba que el algoritmo configurado en propiedades es aceptado. Si no lo es deja el algoritmo por defecto.
	     // Los algoritmos aceptados se pueden ver en la clase TSPAlgorithms (excepto MD5)
	     if (algoritmoHash != null) 
	     {
	     	String temp = algoritmoHash.trim().toUpperCase();
	     	if (TSPAlgoritmos.getPermitidos().contains(algoritmoHash))
	     		this.algoritmoHash = temp;
	     	else {
	     		log.warn(MENSAJE_NO_ALGORITMO_HASH);
	     	}   
	     }
	              
    }
         

    /**
     * Este método genera el Sello de Tiempo
     * @param binarioaSellar fichero binario que se va a sellar
     * @return TimeStampToken en formato binario
     * @throws TSClienteError
     */
    public byte[] generarSelloTiempo(byte[] binarioaSellar) throws TSClienteError
    {
    	
    	
        if (binarioaSellar==null)
        {
        	log.error(MENSAJE_NO_DATOS_SELLO_TIEMPO);
            throw new TSClienteError(I18n.getResource(LIBRERIA_TSA_ERROR_1));
        } 
        else
        {
            log.info(MENSAJE_GENERANDO_SELLO_TIEMPO);
            TimeStampRequestGenerator generadorPeticion = new TimeStampRequestGenerator();
            TimeStampRequest peticion = null;
            TimeStampResponse respuesta = null;
            
            try
            {
                MessageDigest resumen = MessageDigest.getInstance(algoritmoHash);
                resumen.update(binarioaSellar);
                peticion = generadorPeticion.generate(TSPAlgoritmos.getOID(algoritmoHash), resumen.digest());
                log.info(MENSAJE_PETICION_TSA_GENERADA);
            }
            catch(Exception e) 
            {
                log.error(MENSAJE_ERROR_PETICION_TSA);
                throw new TSClienteError(I18n.getResource(LIBRERIA_TSA_ERROR_10));                
            }
            
            cliente.getParams().setParameter(HttpClientParams.SO_TIMEOUT, INT5000);
            
            // Comprueba si hay configurado un proxy
            String servidorProxy = System.getProperty("http.proxyHost");
            if (servidorProxy != null && !servidorProxy.trim().equals(CADENA_VACIA))
            {
            	int puertoProxy = 80;
            	try {
            		puertoProxy = Integer.parseInt(System.getProperty("http.proxyPort"));
            	} catch (NumberFormatException ex) {
            	}
            	cliente.getHostConfiguration().setProxy(servidorProxy, puertoProxy);
            	
        		Credentials defaultcreds = new AuthenticatorProxyCredentials(servidorProxy, CADENA_VACIA);
        		cliente.getState().setProxyCredentials(AuthScope.ANY, defaultcreds);
            }

            PostMethod metodo = new PostMethod(servidorTSA);
            metodo.addRequestHeader(CONTENT_TYPE, APPLICATION_TIMESTAMP_QUERY);
            ByteArrayInputStream datos = null;
            try
            {
                datos = new ByteArrayInputStream(peticion.getEncoded());
            } 
            catch (IOException e)
            {
                log.error(MENSAJE_ERROR_PETICION + e.getMessage());
                throw new TSClienteError(I18n.getResource(LIBRERIA_TSA_ERROR_11) + DOS_PUNTOS_ESPACIO + e.getMessage());
            }
            
            InputStreamRequestEntity rq = new InputStreamRequestEntity (datos);
            metodo.setRequestEntity(rq);
            
            metodo.getParams().setParameter(HttpMethodParams.RETRY_HANDLER,
                    new DefaultHttpMethodRetryHandler(3, false));
                       
            byte[] cuerpoRespuesta = null ;
            try 
            {
                int estadoCodigo = cliente.executeMethod(metodo);
                log.info(MENSAJE_PETICION_TSA_ENVIADA);
                
                if (estadoCodigo != HttpStatus.SC_OK) 
                {
                	
                	
                    log.error( MENSAJE_FALLO_EJECUCION_METODO + metodo.getStatusLine());
                    throw new TSClienteError(I18n.getResource(LIBRERIA_TSA_ERROR_12) + DOS_PUNTOS_ESPACIO + metodo.getStatusLine());
                }
                
                cuerpoRespuesta = metodo.getResponseBody();
                log.info(MENSAJE_RESPUESTA_TSA_OBTENIDA);
                
                try
                {
                    respuesta = new TimeStampResponse(cuerpoRespuesta);
                    try 
                    {
                        
                    	respuesta.validate(peticion);
                    	
                        log.info(MENSAJE_RESPUESTA_TSA_VALIDADA_OK);
                        // Para solucionar bug en libreria bouncycastle
                        //return respuesta.getTimeStampToken().getEncoded();
                        //AppPerfect: Falso positivo
                        ASN1InputStream is = new ASN1InputStream(cuerpoRespuesta);
                        ASN1Sequence seq = ASN1Sequence.getInstance(is.readObject());
                        DEREncodable enc = seq.getObjectAt(1);
                        if (enc == null)
                        	return null;
                        return enc.getDERObject().getEncoded();
                        //Fin Para solucionar bug en libreria bouncycastle
                    } 
                    catch (TSPException e)
                    {
                    	log.error( MENSAJE_RESPUESTA_NO_VALIDA+ e.getMessage());
                        throw new TSClienteError(I18n.getResource(LIBRERIA_TSA_ERROR_9) + DOS_PUNTOS_ESPACIO + e.getMessage());
                    }
                } 
                catch (TSPException e)
                { 
                    log.error(MENSAJE_RESPUESTA_MAL_FORMADA + e.getMessage());
                	throw new TSClienteError(I18n.getResource(LIBRERIA_TSA_ERROR_8) + DOS_PUNTOS_ESPACIO + e.getMessage());
                } 
                catch (IOException e)
                {
                	
                	log.error(MENSAJE_SECUENCIA_BYTES_MAL_CODIFICADA + e.getMessage());
                	throw new TSClienteError(I18n.getResource(LIBRERIA_TSA_ERROR_7) + DOS_PUNTOS_ESPACIO + e.getMessage());
                }               
            } 
            catch (HttpException e) 
            {
                log.error(MENSAJE_VIOLACION_PROTOCOLO_HTTP + e.getMessage());
            	throw new TSClienteError(I18n.getResource(LIBRERIA_TSA_ERROR_6) + DOS_PUNTOS_ESPACIO + e.getMessage());
            } 
            catch (IOException e) 
            {
            	String mensajeError = I18n.getResource(LIBRERIA_TSA_ERROR_4) + DOS_PUNTOS_ESPACIO + servidorTSA;
            	log.error(MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP+ e.getMessage());
            	 
            	throw new TSClienteError(mensajeError);
            } 
            finally 
            {
                // Termina la conexión
                metodo.releaseConnection();
            }
        }
    }
    
    
    /**
     * Este método valida el Sello de Tiempo
     * @param binarioaSellar fichero binario a validar
     * @param sellodeTiempo El Sello de Tiempo se ingresa en formato binario
     * @return TSValidacion Valores TSA
     * @throws NoSuchAlgorithmException
     * @throws TSPException
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws CertStoreException
     * @throws TSClienteError
     */
    public static TSValidacion validarSelloTiempo(byte[] binarioaSellar, byte[] sellodeTiempo)
    		 throws NoSuchAlgorithmException,
    				TSPException,
    				IOException,
    				NoSuchProviderException,
    				CertStoreException, TSClienteError {
    	
//    	Set permitidos = new HashSet(Arrays.asList(TSPAlgoritmos.getValoresPermitidos()));
//    	si el algoritmo pasado no es permitido o es nulo se usa el algortimo por defecto
    	
        TimeStampToken tst = null;
        TSValidacion tsv = new TSValidacion();
        
        try {
        	tst = new TimeStampToken(new CMSSignedData(sellodeTiempo));
		} 
        catch (CMSException e) 
        {
        	// Intenta obtenerlo como una TimeStampResp
        	try {
	        	TimeStampResponse tsr = new TimeStampResponse(sellodeTiempo);
	        	tst = tsr.getTimeStampToken();
	        	if (tst == null)
	    			throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_2));
        	} catch(TSPException ex) {
    			throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_2));
        	} catch (IOException ex) {
    			throw new TSClienteError(I18n.getResource(ConstantesTSA.LIBRERIA_TSA_ERROR_2));
        	}
		}   	
        
        tsv.setTst(tst);
        TimeStampTokenInfo tokenInfo = tst.getTimeStampInfo();
        
        MessageDigest resumen = TSPAlgoritmos.getDigest(tokenInfo.getMessageImprintAlgOID());
        if (resumen == null) {
        	tsv.setRespuesta(false);
        	return tsv;
        }
        
        resumen.update(binarioaSellar);
		if (MessageDigest.isEqual(resumen.digest(), tst.getTimeStampInfo().getMessageImprintDigest())){
	        //TimeStampTokenInfo tokenInfo = tst.getTimeStampInfo();	                       
			SimpleDateFormat formato = new SimpleDateFormat(FORMATO_FECHA);
			tsv.setFecha(formato.format(tokenInfo.getGenTime())  );
			tsv.setFechaDate(tokenInfo.getGenTime());
	        
			GenTimeAccuracy precision = tokenInfo.getGenTimeAccuracy();
			tsv.setPrecision(precision);
			
			long accuLong = 0;
			if (precision != null) {
				accuLong =  (precision.getMicros()  * 1L) + 
							(precision.getMillis()  * 1000L) + 
							(precision.getSeconds() * 1000000L);
			}
			tsv.setPrecisionLong(accuLong);	        
	        
	        tsv.setSello(tokenInfo.getSerialNumber());
	        tsv.setFirmaDigest(new String(Base64Coder.encode(tokenInfo.getMessageImprintDigest())));
	        tsv.setRespuesta(true);
	        tsv.setSelloAlg(tokenInfo.getMessageImprintAlgOID());
	        tsv.setEmisor(tst.getSID().getIssuer());
		} else {
			tsv.setRespuesta(false);
		}
        return tsv;
    }
    
/**
 * Ejemplo de validacion del sello de tiempo
 * @param args
 */
    public static void main(String[] args){
//    	TSCliente cliente = new TSCliente("http://minister-6vp1kq.mityc.age:9207","SHA-1", null, 0);
//        byte[] firma = Base64.decode(("X1MlQzZRNqBeJR2hjunePlD+ywlkdgaBAo3QDRhItXGhb1k4FffA6V2w5KZoSjPCaDhMgwcTXxz3"+
//        		"UThBmRlOxfZaPCpne63jRlkp63g2IclrmBRKFgsb+Wzb0/pNh/ITffiARrRpYqtO7M92V1+GZbph"+
//        		"m8swQHEJlCtiOyJvwPsFkq5LyB8Zm9pBhUo12oVWnU2sCi9EMl1wIGpr71o7rm0XeudCnFS+45pb"+
//        		"1uQNOILSYizSEnFZpa81/nSgjlW93q0xcE5wrzBsHvUPvhRHydXyYzITXYiSKSFFBuM/N/dcrn57"+
//        "HoaCGoJP6zQ/Wd00c7AopMxM4qFcLSuljIRSag==")) ;
//        byte[] tiempoSello = Base64.decode(("MIAGCSqGSIb3DQEHAqCAMIICdgIBAzELMAkGBSsOAwIaBQAwgZwGCyqGSIb3DQEJEAEEoIGMBIGJMIGGAgEBBgUqAwQFBjAhMAkGBSsOAwIaBQAEFLLvwLC3nEd02gNUWVajJdZXzgCuAhDYJoYNZgUCsQnl459uAPTjGA8yMDA3MDQxODE1MjIyM1qgNKQyMDAxCzAJBgNVBAYTAkVTMQ0wCwYDVQQLEwRERU1PMRIwEAYDVQQDEwlNSVRZQyBUU1AxggHDMIIBvwIBATBEMDAxCzAJBgNVBAYTAkVTMQ0wCwYDVQQLEwRERU1PMRIwEAYDVQQDEwlNSVRZQyBUU1ACEACk/CLM7Wk3DZLGU0wsw+4wCQYFKw4DAhoFAKCB1jAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTA3MDQxODE1MjIyM1owIwYJKoZIhvcNAQkEMRYEFEF7oHc9iR2uGAGjO+rta/Qqy5OpMHUGCyqGSIb3DQEJEAIMMWYwZDBiMGAEFCzqcQksWEIV1+dMt+JE/PEKjp1zMEgwNKQyMDAxCzAJBgNVBAYTAkVTMQ0wCwYDVQQLEwRERU1PMRIwEAYDVQQDEwlNSVRZQyBUU1ACEACk/CLM7Wk3DZLGU0wsw+4wDQYJKoZIhvcNAQEBBQAEgYCMr1HUe8xtsJ+a4cwQoV1DeTarNP4BLpSDM0qQky/ZKJgmsldaIUIG9j246njLAMGBURU1rbi+HhOKbIVImjWk7G/hzn/sUQsgrIqdffoGW5PSnVR5hKBPsTDUvdnZ8LvHLCLbir44TDVhF2ewzjp9lYXjM9/cMNU8cS3vePmftgAAAAA=")) ;
//        TSValidacion tsv = null;
//        try {
//            tsv = cliente.validarSelloTiempo(firma, tiempoSello);
//            
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        }
//        
//        log.info("------------------------------------------");
//        if (tsv != null){
//        	log.info(tsv.getFecha());   
//        }
    }
}

