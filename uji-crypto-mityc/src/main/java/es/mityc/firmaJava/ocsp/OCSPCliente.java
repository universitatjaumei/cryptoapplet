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

package es.mityc.firmaJava.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ResourceBundle;
import java.util.Vector;

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
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

import es.mityc.firmaJava.configuracion.Configuracion;
import es.mityc.firmaJava.ocsp.config.ConfigProveedores;
import es.mityc.firmaJava.ocsp.config.ServidorOcsp;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class OCSPCliente implements ConstantesOCSP {

    private static final Integer INT_5000 = new Integer(5000);
	
	private String 	servidorURL;

    static Log log = LogFactory.getLog(OCSPCliente.class);


    /**
     * Constructor de la clase OCSPCliente sin Proxy
     * @param servidorURL Servidor URL
     */
    public OCSPCliente(String servidorURL)
    {
      this.servidorURL = servidorURL;
    }


    /**
     * Este método valida el Certificado contra un servidor OCSP
     * @param certificadoUsuario Certificado
     * @return respuestaOCSP tipo número de respuesta y mensaje correspondiente
     * @throws OCSPClienteError Errores del cliente OCSP
     */
    public RespuestaOCSP validateCert(X509Certificate certificadoUsuario) throws OCSPClienteError, OCSPProxyException
    {
    	
    	RespuestaOCSP respuesta = new RespuestaOCSP();
    	
    	// Añadimos el proveedor BouncyCastle
        Security.addProvider(new BouncyCastleProvider());
        OCSPReqGenerator generadorPeticion = new OCSPReqGenerator();
        OCSPReq peticionOCSP = null;
        OCSPResp respuestaOCSP = null;
        CertificateID certificadoId = null;
        
        // Buscamos el certificado emisor del certificado que nos atañe.
        ResourceBundle propiedades = ResourceBundle.getBundle(RUTA_PAQUETE_CERTIFICADOS);
        String certificadosCACadena = propiedades.getString(FICHERO_CA) ;
        String[] listaCertificadosCA = certificadosCACadena.split(COMA) ;
        Vector <X509Certificate> certRef = new Vector<X509Certificate>();
        certRef.add(certificadoUsuario);
        X509Certificate certTemp = null;

    	int t = 0;
    	boolean encontrado = false;
    	X509Certificate certificate = null;
    	Principal issuerDN = null;
    	Principal subjectDN = null;
    	boolean flag = true;
    	do
    	{
    		t++;
    		int longitudListaCertificados = listaCertificadosCA.length;
	        for (int a=0 ; a < longitudListaCertificados ;a++)
	        {
	            StringBuffer sbCertif = new StringBuffer(RUTA_CERTIFICADOS);
	       	    sbCertif.append(listaCertificadosCA[a]);
	            InputStream entradaStream = getClass().getResourceAsStream(String.valueOf(sbCertif));
	            CertificateFactory cf;
	            try
	            {
	                cf = CertificateFactory.getInstance(X509);
	                certTemp=(X509Certificate)cf.generateCertificate(entradaStream);
	                entradaStream.close();
	            }
	            catch (Exception ex)
	            {
	            	log.error(ERROR_LEER_CERTIFICADOS_CONFIANZA_ALMACENADOS, ex);
	            	throw new OCSPClienteError(ERROR_LEER_CERTIFICADOS_CONFIANZA_ALMACENADOS); 
	            }

	            if (certTemp != null && certRef.elementAt(t-1).getIssuerDN().equals(certTemp.getSubjectDN()))
	            {
	            	certRef.add(certTemp);
	            	encontrado = true;
	                break ;
	            }
	        }
	        if (!encontrado)   {
	            // No se ha encontrado el certificado de la CA en el almacen local
            	log.error(ERROR_CERTIFICADO_CA_ALMACEN_LOCAL);
                throw new OCSPClienteError(I18n.getResource(LIBRERIA_OCSP_ERROR_1));
	        }
//	      	certRef.add(null);
	        
	        if (t <= certRef.size())
	        	certificate = certRef.elementAt(t);
	        else
	        	certificate = null;
	        issuerDN = certificate.getIssuerDN();
	        subjectDN = certificate.getSubjectDN();
	        flag = issuerDN.equals(subjectDN);
	        
    	} while (certificate!=null && !flag);

        // No se ha encontrado el certificado de la CA en el almacen local
        if (certRef.elementAt(1) == null )
        {
        	log.error(ERROR_CERTIFICADO_CA_ALMACEN_LOCAL);
            throw new OCSPClienteError(I18n.getResource(LIBRERIA_OCSP_ERROR_1));
        }

        respuesta.setRefCerts(certRef);

        try {
            certificadoId = new CertificateID(CertificateID.HASH_SHA1, certRef.elementAt(1), certificadoUsuario.getSerialNumber(), "BC");
            log.info(MENSAJE_CREADO_INDENTIFICADO);
            
        } catch (OCSPException e) {
        	
            log.info( MENSAJE_ERROR_GENERAR_IDENTIFICADOR + e.getMessage());
            throw new OCSPClienteError(I18n.getResource(LIBRERIA_OCSP_ERROR_2) + DOS_PUNTOS_ESPACIO + e.getMessage());
        }

        generadorPeticion.addRequest(certificadoId);

        try
        {
            peticionOCSP = generadorPeticion.generate();
            log.info(MENSAJE_PETICION_OCSP_GENERADA);
        }
        catch (OCSPException e)
        {
            log.error( ERROR_MENSAJE_GENERAR_PETICION_OCSP + e.getMessage());
            throw new OCSPClienteError(I18n.getResource(LIBRERIA_OCSP_ERROR_3) + DOS_PUNTOS_ESPACIO + e.getMessage());
        }

        
        HttpClient cliente = new HttpClient();
        
        cliente.getParams().setParameter(HttpClientParams.SO_TIMEOUT, INT_5000);

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
        if (false == Configuracion.isEmpty(servidorURL)  
        		&& 
        		servidorURL.trim().equalsIgnoreCase(USAR_OCSP_MULTIPLE)
        ) {

        	ServidorOcsp servidor = ConfigProveedores.getServidor(certificadoUsuario);

        	if (null != servidor) {

        		servidorURL = servidor.getUrl().toString();
        		log.debug(DEBUG_SERVIDOR_OCSP_ENCONTRADO + servidorURL);
        	} else {
        		log.error(I18n.getResource(LIBRERIA_OCSP_ERROR_12));
        		servidorURL = CADENA_VACIA;
        		throw new OCSPClienteError(I18n.getResource(LIBRERIA_OCSP_ERROR_12));

        	}

        }


        PostMethod metodo = new PostMethod(servidorURL);
        
        metodo.addRequestHeader(CONTENT_TYPE, APPLICATION_OCSP_REQUEST);
        ByteArrayInputStream datos = null;

        try
        {
            datos = new ByteArrayInputStream(peticionOCSP.getEncoded());

        }
        catch (IOException e)
        {
        	
        	log.error( MENSAJE_ERROR_LEER_PETICION + e.getMessage());
            throw new OCSPClienteError(I18n.getResource(LIBRERIA_OCSP_ERROR_4) + DOS_PUNTOS_ESPACIO + e.getMessage());
        }

        InputStreamRequestEntity rq = new InputStreamRequestEntity (datos);
        metodo.setRequestEntity(rq);
        
        metodo.getParams().setParameter(HttpMethodParams.RETRY_HANDLER,
                new DefaultHttpMethodRetryHandler(3, false));

        try
        {
        	int estadoCodigo = cliente.executeMethod(metodo);
            log.info(MENSAJE_PETICION_ENVIADA);
            

            if (estadoCodigo != HttpStatus.SC_OK)
            {
            	if (estadoCodigo == HttpStatus.SC_PROXY_AUTHENTICATION_REQUIRED)
                	throw new OCSPProxyException(MENSAJE_PROXY_AUTENTICADO);
                else if (estadoCodigo == HttpStatus.SC_USE_PROXY)
                	throw new OCSPProxyException(MENSAJE_PROXY_POR_CONFIGURAR);
                else {
                	log.error( MENSAJE_FALLO_EJECUCION_METODO + metodo.getStatusLine());
                	throw new OCSPClienteError(I18n.getResource(LIBRERIA_OCSP_ERROR_9) + DOS_PUNTOS_ESPACIO + metodo.getStatusLine());
                }
            }

            byte[] cuerpoRespuesta = metodo.getResponseBody();
            log.info(MENSAJE_RESPUESTA_OBTENIDA);
            

            try
            {
            	respuestaOCSP = new OCSPResp(cuerpoRespuesta);
            }
            catch (IOException e)
            {
            	log.error( MENSAJE_ERROR_SECUENCIA_BYTES_RESPUESTA + e.getMessage());
                throw new OCSPClienteError(I18n.getResource(LIBRERIA_OCSP_ERROR_5) + DOS_PUNTOS_ESPACIO + e.getMessage());
            }

            /*
              Estados de la respuesta OCSP
                successful            (0) La respuesta tiene una confirmación válida
                malformedRequest      (1) La petición no se realizó de forma correcta
                internalError         (2) Error interno
                tryLater              (3) Vuelva a intentarlo
                                       -  (4) no se utiliza
                sigRequired           (5) La petición debe estar firmada
                unauthorized          (6) No se ha podido autorizar la petición

            */

            if (respuestaOCSP.getStatus() != 0)
            {
            	log.info(MENSAJE_OCSP_NOT_SUCCESSFUL);
            	switch (respuestaOCSP.getStatus())
            	{
		            case 1:
		            			log.warn(MENSAJE_OCSP_MALFORMED_REQUEST);
		            			respuesta.setNroRespuesta(MALFORMEDREQUEST);
		            			respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_OCSP_RESPUESTA_1));
		            			
		            			break;
		            case 2:
		            			log.warn(MENSAJE_OCSP_INTERNAL_ERROR);
		            			respuesta.setNroRespuesta(INTERNALERROR);
		            			respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_OCSP_RESPUESTA_2));
		            			break;
		            case 3:
		            			log.warn(MENSAJE_OCSP_TRY_LATER);
		            			respuesta.setNroRespuesta(TRYLATER);
		            			respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_OCSP_RESPUESTA_3));
		            			break;
		            case 5:
		            			log.warn(MENSAJE_OCSP_SIG_REQUIRED);
		            			respuesta.setNroRespuesta(SIGREQUIRED);
		            			respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_OCSP_RESPUESTA_4));
		            			break;
		            case 6:
		            			log.warn(MENSAJE_OCSP_UNAUTHORIZED);
		            			respuesta.setNroRespuesta(UNAUTHORIZED);
		            			respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_OCSP_RESPUESTA_5));
		            			break;
            	}
            	return respuesta;
            }
            else
            {
	            try
	            {
	            	log.info(MENSAJE_OCSP_SUCCESSFUL);
	                BasicOCSPResp respuestaBasica = (BasicOCSPResp)respuestaOCSP.getResponseObject();
	                SingleResp[] arrayRespuestaBasica = respuestaBasica.getResponses();
	                respuesta.setTiempoRespuesta(respuestaBasica.getProducedAt());
	                ResponderID respID = respuestaBasica.getResponderId().toASN1Object();
	                respuesta.setResponder(respID);
	                StringBuffer mensaje = new StringBuffer(MENSAJE_RECIBIDO_ESTADO_NO_DEFINIDO);

	                for (int i = 0; i<arrayRespuestaBasica.length;i++)
	                {
	                	Object certStatus = arrayRespuestaBasica[i].getCertStatus();
	                	if (certStatus == null)
	                    {
	                    	log.info(ESTADO_CERTIFICADO_GOOD);
	                    	respuesta.setNroRespuesta(GOOD);
	                    	respuesta.setMensajeRespuesta(new String(Base64Coder.encode(respuestaOCSP.getEncoded())));
	                    	respuesta.setRespuesta(cuerpoRespuesta);
	                    }
	                	else if (certStatus instanceof RevokedStatus)
	                    {
	                    	log.info(ESTADO_CERTIFICADO_REVOKED);
	                        respuesta.setNroRespuesta(REVOKED);

	                        /*
	                        Razones de revocación
	                        	unused 					(0) Sin uso
	                        	keyCompromise 			(1) Se sospecha que la clave del certificado ha quedado comprometida
	                        	cACompromise			(2) Se sospecha que la clave que firmó el certificado ha quedado comprometida
	                        	affiliationChanged		(3) Se han cambiado los datos particulares del certificado
	                        	superseded	      		(4) El certificado ha sido reemplazado por otro
	                        	cessationOfOperation	(5) El certificado ha dejado de operar
	                        	certificateHold 		(6) El certificado momentáneamente ha dejado de operar
							*/

	                        RevokedStatus revoked = (RevokedStatus)certStatus;
	                        if (revoked.hasRevocationReason())
	                        {
		                        switch (revoked.getRevocationReason())
		                        {
		                        
		                        	case 1:
		                        			respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_RAZON_REVOCACION_1));
		                        			break;
		                        	case 2:
	                        				respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_RAZON_REVOCACION_2));
	                        				break;
		                        	case 3:
	                        				respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_RAZON_REVOCACION_3));
	                        				break;
		                        	case 4:
	                        				respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_RAZON_REVOCACION_4));
	                        				break;
		                        	case 5:
	                        				respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_RAZON_REVOCACION_5));
	                        				break;
		                        	case 6:
	                        				respuesta.setMensajeRespuesta(I18n.getResource(LIBRERIA_RAZON_REVOCACION_6));
	                        				break;
		                        	default:
		                        			respuesta.setMensajeRespuesta(CADENA_VACIA);
		                        }
	                        }
	                        else
	                        	respuesta.setMensajeRespuesta(CADENA_VACIA);
	                    }
	                    else if (certStatus instanceof UnknownStatus)
	                    {
	                    	
	                    	log.info(ESTADO_CERTIFICADO_UNKNOWN);
	                    	respuesta.setNroRespuesta(UNKNOWN) ;
	                    	// aqui (I18n.getResource
	                    	respuesta.setMensajeRespuesta(MENSAJE_RESPUESTA_SERVIDOR_ESTADO_DESCONOCIDO);
	                    }
	                    else
	                    {
	                    	mensaje.append(arrayRespuestaBasica[i].getCertStatus().getClass().getName());
	                    	log.info( mensaje.toString());
	                    	respuesta.setNroRespuesta(ERROR) ;
	                    	respuesta.setMensajeRespuesta(arrayRespuestaBasica[i].getCertStatus().getClass().getName());
	                    }
	                }
	            }
	            catch (OCSPException e)
	            {
	            	log.error( MENSAJE_ERROR_RESPUESTA_OCPS_BASICA + e.getMessage());
	            	throw new OCSPClienteError(I18n.getResource(LIBRERIA_OCSP_ERROR_6) + DOS_PUNTOS_ESPACIO + e.getMessage());
	            }
            }

        }
        catch (HttpException e)
        {
        	log.error( MENSAJE_VIOLACION_HTTP + e.getMessage());
        	throw new OCSPClienteError(I18n.getResource(LIBRERIA_OCSP_ERROR_7) + DOS_PUNTOS_ESPACIO + e.getMessage());
        }
        catch (IOException e)
        {
        	String mensajeError = I18n.getResource(LIBRERIA_OCSP_ERROR_10) + DOS_PUNTOS_ESPACIO + servidorURL;
        	log.error( MENSAJE_ERROR_CONEXION_SERVIDOR_OCSP + e.getMessage());
//            if (servidorProxy != null)
//            {
//            	mensajeError = mensajeError  + NUEVA_LINEA + I18n.getResource(LIBRERIA_OCSP_ERROR_11) + DOS_PUNTOS_ESPACIO + servidorProxy + DOS_PUNTOS + puertoProxy;
//            	log.error( MENSAJE_UTILIZA_SERVIDOR_PROXY + servidorProxy + DOS_PUNTOS + puertoProxy);
//            	
//            }
        	throw new OCSPClienteError(mensajeError);
        }
        finally
        {
            Security.removeProvider(BC);
            metodo.releaseConnection();
        }
        return respuesta ;
    }
}
