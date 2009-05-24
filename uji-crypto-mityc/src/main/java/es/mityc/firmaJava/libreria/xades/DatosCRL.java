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

import java.security.cert.X509CRL;
import java.util.Date;

import es.mityc.firmaJava.trust.ConfianzaEnum;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class DatosCRL {
	
	private String issuer = null;
	private Date fechaEmision = null;
	private Date fechaCaducidad = null;
	private X509CRL x509CRL = null;
	private ConfianzaEnum esCertConfianza = ConfianzaEnum.NO_REVISADO;
	
	
	public DatosCRL() {}
	
	/**
	 * Almacena información referente a una lista de revocación de certificados
	 * 
	 * @param issuer  .- Emisor de la CRL
	 * @param fechaEmision .- La fecha de emisión de la lista
	 * @param fechaCaducidad .- La fecha de caducidad de la lista
	 * @param x509CRL .- La lista propiamente dicha
	 * @param esCertConfianza .- Booleano que indica si la CRL es considerada de confianza
	 */
	public DatosCRL(String issuer,
			Date fechaEmision,
			Date fechaCaducidad,
			X509CRL x509CRL,
			ConfianzaEnum esCertConfianza) {
		this.issuer = issuer;
		this.fechaEmision = fechaEmision;
		this.fechaCaducidad = fechaCaducidad;
		this.x509CRL = x509CRL;
		this.esCertConfianza = esCertConfianza;
	}

	public String getIssuer() {
		return issuer;
	}
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	public Date getFechaEmision() {
		return fechaEmision;
	}
	public void setFechaEmision(Date fechaEmision) {
		this.fechaEmision = fechaEmision;
	}
	public Date getFechaCaducidad() {
		return fechaCaducidad;
	}
	public void setFechaCaducidad(Date fechaCaducidad) {
		this.fechaCaducidad = fechaCaducidad;
	}
	public X509CRL getX509CRL() {
		return x509CRL;
	}
	public void setX509CRL(X509CRL x509crl) {
		x509CRL = x509crl;
	}
	public ConfianzaEnum esCertConfianza() {
		return esCertConfianza;
	}
	public void setEsCertConfianza(ConfianzaEnum esCertConfianza) {
		this.esCertConfianza = esCertConfianza;
	}
}