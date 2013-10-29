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

import java.util.Date;

import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.ocsp.OCSPResp;

import es.mityc.firmaJava.trust.ConfianzaEnum;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class DatosOCSP {
	
	private ResponderID responderId = null;
	private Date fechaConsulta = null;
	private String certConsultado = null;
	private OCSPResp respuestaOCSP = null;
	private ConfianzaEnum esCertConfianza = ConfianzaEnum.NO_REVISADO;
	
	public DatosOCSP() {}
	
	/**
	 * Almacena información referente a una consulta OCSP
	 * 
	 * @param responderId .- Identificador del emisor de la respuesta OCSP
	 * @param fechaConsulta .- Fecha en la que se realizó la consulta
	 * @param certConsultado .- Certificado consultado al servidor OCSP
	 * @param respuestaOCSP .- El objeto OCSP que almacena la respuesta obtenida  
	 * @param esCertConfianza .- Booleano que indica si la respuesta es considerada de confianza  
	 */
	public DatosOCSP(ResponderID responderId,
			Date fechaConsulta,
			String certConsultado,
			OCSPResp respuestaOCSP,
			ConfianzaEnum esCertConfianza) {
		this.responderId = responderId;
		this.fechaConsulta = fechaConsulta;
		this.certConsultado = certConsultado;
		this.respuestaOCSP = respuestaOCSP;
		this.esCertConfianza = esCertConfianza;
	}
	
	public ResponderID getResponderId() {
		return responderId;
	}
	public void setResponderId(ResponderID responderId) {
		this.responderId = responderId;
	}
	public String getCertConsultado() {
		return certConsultado;
	}
	public void setCertConsultado(String certConsultado) {
		this.certConsultado = certConsultado;
	}
	public Date getFechaConsulta() {
		return fechaConsulta;
	}
	public void setFechaConsulta(Date fechaConsulta) {
		this.fechaConsulta = fechaConsulta;
	}
	public OCSPResp getRespuestaOCSP() {
		return respuestaOCSP;
	}
	public void setRespuestaOCSP(OCSPResp respuestaOCSP) {
		this.respuestaOCSP = respuestaOCSP;
	}
	public ConfianzaEnum esCertConfianza() {
		return esCertConfianza;
	}
	public void setEsCertConfianza(ConfianzaEnum esCertConfianza) {
		this.esCertConfianza = esCertConfianza;
	}	
}
