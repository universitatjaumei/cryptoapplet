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

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;

/**
 * Clase encargada de almacenar la informacion de las validaciones OCSP
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class RespuestaOCSP
{
	public enum TIPOS_RESPONDER {BY_NAME, BY_KEY};
	
	private int 						nroRespuesta;
	private String						mensajeRespuesta;
	private byte[] 						respuesta;
	private Date 						tiempoRespuesta;
	private Vector<X509Certificate> 	refCerts;
//	private String						respuestaID;
	private TIPOS_RESPONDER				tipoResponder;
	private String						valorResponder;


	/**
	 * Constructor de la clase respuestaOCSP
	 * @param nroRespuesta tipo de respuesta recibida del servidor OCSP
	 * @param mensajeRespuesta mensaje que corresponde con el tipo de respuesta
	 */
	public RespuestaOCSP(int nroRespuesta, byte[] respuesta, String mensajeRespuesta, Date tiempoRespuesta, String respuestaID, Vector<X509Certificate> refCerts)
	{
		this.nroRespuesta 		=	nroRespuesta;
		this.respuesta			=	respuesta.clone();
		this.mensajeRespuesta	=	mensajeRespuesta;
		this.tiempoRespuesta	=	new Date(tiempoRespuesta.getTime());
		this.refCerts			=	refCerts;
	}
	


	/**
	 * Constructor de la clase respuestaOCSP
	 * @param nroRespuesta tipo de respuesta recibida del servidor OCSP
	 * @param mensajeRespuesta mensaje que corresponde con el tipo de respuesta
	 */
	public RespuestaOCSP(int nroRespuesta, String mensajeRespuesta)
	{
		this.nroRespuesta 		=	nroRespuesta;
		this.mensajeRespuesta	=	mensajeRespuesta;
	}


	/**
	 * Constructor vacío de la clase respuestaOCSP
	 */
	public RespuestaOCSP()
	{
		//No hace nada
	}

	/**
	 * Obtiene el cuerpo de la respuesta del servidor OCSP
	 * @return cuerpo de la respuesta
	 */
	public byte[] getRespuesta()
	{
		return respuesta.clone();
	}

	/**
	 * Establece el cuerpo de la respuesta del servidor OCSP
	 * @param respuesta cuerpo de la respuesta
	 */
	public void setRespuesta(byte[] respuesta)
	{
		this.respuesta = respuesta.clone();
	}
	
	/**
	 * Obtiene el mensaje de la respuesta del servidor OCSP
	 * @return mensaje de la respuesta
	 */
	public String getMensajeRespuesta()
	{
		return mensajeRespuesta;
	}

	/**
	 * Establece el mensaje de la respuesta del servidor OCSP
	 * @param mensajeRespuesta mensaje de la respuesta
	 */
	public void setMensajeRespuesta(String mensajeRespuesta)
	{
		this.mensajeRespuesta = mensajeRespuesta;
	}

	/**
	 * Obtiene el tipo de respuesta que ha devuelto el servidor OCSP
	 * @return tipo de respuesta
	 */
	public int getNroRespuesta()
	{
		return nroRespuesta;
	}

	/**
	 * Establece el tipo de respuesta que ha devuelto el servidor OCSP
	 * @param nroRespuesta tipo de respuesta
	 */
	public void setNroRespuesta(int nroRespuesta)
	{
		this.nroRespuesta = nroRespuesta;
	}

	/**
	 *
	 * @return
	 */
	public Vector<X509Certificate> getRefCerts() {
		return refCerts;
	}

	/**
	 *
	 * @param refCerts
	 */
	public void setRefCerts(Vector<X509Certificate> refCerts) {
		this.refCerts = refCerts;
	}

	/**
	 *
	 * @return
	 */
	public Date getTiempoRespuesta() {
		return new Date(tiempoRespuesta.getTime());  
	}

	/**
	 *
	 * @param tiempoRespuesta
	 */
	public void setTiempoRespuesta(Date tiempoRespuesta) {
		this.tiempoRespuesta = new Date(tiempoRespuesta.getTime());
	}



	public TIPOS_RESPONDER getTipoResponder() {
		return tipoResponder;
	}



	public void setResponder(ResponderID responder) {
        ASN1TaggedObject tagged = (ASN1TaggedObject)responder.toASN1Object();
		switch (tagged.getTagNo()) {
			case 1:
				valorResponder = X509Name.getInstance(tagged.getObject()).toString();
				X509Principal certX509Principal = new X509Principal(valorResponder);
				X500Principal cerX500Principal = new X500Principal(certX509Principal.getDEREncoded());
				valorResponder = cerX500Principal.getName();
				tipoResponder = TIPOS_RESPONDER.BY_NAME;
				break;
			case 2:
				ASN1OctetString octect = (ASN1OctetString)tagged.getObject();
				valorResponder = new String(Base64Coder.encode(octect.getOctets()));
				tipoResponder = TIPOS_RESPONDER.BY_KEY;
				break;
		}
	}



	public String getValorResponder() {
		return valorResponder;
	}

}