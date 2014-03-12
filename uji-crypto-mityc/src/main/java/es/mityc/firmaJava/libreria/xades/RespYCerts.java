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

import java.security.cert.X509Certificate;

import es.mityc.firmaJava.ocsp.RespuestaOCSP.TIPOS_RESPONDER;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class RespYCerts {
	private byte[] respOCSP = null;
	private X509Certificate x509Cert = null;
	private String tiempoRespuesta = null;
	private String valorResponderID = null;
	private TIPOS_RESPONDER tipoResponder;
	private String idCertificado = null;
	private String idOCSP = null; 
	
	public RespYCerts() {
		// No hace nada
	}
	
	public void setRespOCSP(byte[] respOCSP) {
		this.respOCSP = respOCSP.clone();
	}
	
	public void setX509Cert(X509Certificate x509Cert) {
		this.x509Cert = x509Cert;
	}
	
	public void setTiempoRespuesta(String tiempo) {
		this.tiempoRespuesta = tiempo;
	}
	
	public void setResponder(String id, TIPOS_RESPONDER tipoResponder) {
		this.valorResponderID = id;
		this.tipoResponder = tipoResponder;
	}
	
	public byte[] getRespOCSP() {
		return respOCSP.clone();
	}
	
	public X509Certificate getX509Cert() {
		return x509Cert;
	}
	
	public String getTiempoRespuesta() {
		return tiempoRespuesta;
	}
	
	public String getResponderID() {
		return valorResponderID;
	}
	
	public TIPOS_RESPONDER getTipoResponder() {
		return tipoResponder;
	}

	public String getIdCertificado() {
		return idCertificado;
	}

	public void setIdCertificado(String idCertificado) {
		this.idCertificado = idCertificado;
	}

	public String getIdOCSP() {
		return idOCSP;
	}

	public void setIdOCSP(String idOCSP) {
		this.idOCSP = idOCSP;
	}
}