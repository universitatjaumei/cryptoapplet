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

import java.security.cert.CertPath;
import java.util.ArrayList;
import java.util.Date;

import es.mityc.firmaJava.policy.PolicyResult;
import es.mityc.firmaJava.trust.ConfianzaEnum;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class DatosFirma {
	
	private CertPath cadenaFirma = null;
	private ConfianzaEnum esCadenaConfianza = ConfianzaEnum.NO_REVISADO;
	private DatosTipoFirma tipoFirma = null;
	private ArrayList<DatosSelloTiempo>  datosSelloTiempo = null;
	private ArrayList<DatosCRL> datosCRL = null;
	private ArrayList<DatosOCSP> datosOCSP = null;
	private Date fechaFirma = null;
	private ArrayList<String> roles = null;
	private ArrayList<PolicyResult> politicas = null;
	private XAdESSchemas esquema = null;
	
	public DatosFirma() {}
	
	/**
	 * Almacena informacion referente a una validación de Firma
	 * 
	 * @param cadenaFirma .- Cadena de certificados utilizados en la firma
	 * @param esCadenaConfianza .- Booleano que indica si la cadena está consierada de confianza
	 * @param tipoFirma .- Tipo de firma XAdES (BES, EPES, T...)
	 * @param datosSelloTiempo .- Recoge la información de cada sello de tiempo de la firma
	 * @param datosCRL .- Recoge la información de cada lista de revocación de la firma
	 * @param datosOCSP .- Recoge información de cada respuesta OCSP de la firma
	 * @param fechaFirma .- Fecha de firma recuperada del nodo SigningTime
	 * @param roles .- roles definidos en la firma
	 * @param politicas .- Recoge información de las firmas incluidas en la firma
	 * @param esquema .- Esquema utilizado en la firma
	 */
	public DatosFirma(CertPath cadenaFirma,
			ConfianzaEnum esCadenaFirma,
			DatosTipoFirma tipoFirma,
			ArrayList<DatosSelloTiempo> datosSelloTiempo,
			ArrayList<DatosCRL> datosCRL,
			ArrayList<DatosOCSP> datosOCSP,
			Date fechaFirma,
			ArrayList<String> roles,
			ArrayList<PolicyResult> politicas, 
			XAdESSchemas esquema) {
		
		this.cadenaFirma = cadenaFirma;
		this.esCadenaConfianza = esCadenaFirma;
		this.tipoFirma = tipoFirma;
		this.datosSelloTiempo = datosSelloTiempo;
		this.datosCRL = datosCRL;
		this.datosOCSP = datosOCSP;
		this.fechaFirma = fechaFirma;
		this.roles = roles;
		this.politicas = politicas;
		this.esquema = esquema;
	}	
	
	public CertPath getCadenaFirma() {
		return cadenaFirma;
	}
	public void setCadenaFirma(CertPath cadenaFirma) {
		this.cadenaFirma = cadenaFirma;
	}
	public ConfianzaEnum esCadenaConfianza() {
		return esCadenaConfianza;
	}
	public void setEsCadenaConfianza(ConfianzaEnum esCadenaConfianza) {
		this.esCadenaConfianza = esCadenaConfianza;
	}
	public DatosTipoFirma getTipoFirma() {
		return tipoFirma;
	}
	public void setTipoFirma(DatosTipoFirma tipoFirma) {
		this.tipoFirma = tipoFirma;
	}
	public ArrayList<DatosOCSP> getDatosOCSP() {
		if (datosOCSP != null)
			return datosOCSP;
		else
			return new ArrayList<DatosOCSP>();
	}
	public ArrayList<DatosCRL> getDatosCRL() {
		return datosCRL;
	}
	public void setDatosCRL(ArrayList<DatosCRL> datosCRL) {
		this.datosCRL = datosCRL;
	}
	public void setDatosOCSP(ArrayList<DatosOCSP> datosOCSP) {
		this.datosOCSP = datosOCSP;
	}
	public ArrayList<DatosSelloTiempo> getDatosSelloTiempo() {
		if (datosSelloTiempo != null)
			return datosSelloTiempo;
		else 
			return new ArrayList<DatosSelloTiempo>();
	}
	public void setDatosSelloTiempo(ArrayList<DatosSelloTiempo> datosSelloTiempo) {
		this.datosSelloTiempo = datosSelloTiempo;
	}
	public Date getFechaFirma() {
		return fechaFirma;
	}
	public void setFechaFirma(Date fechaFirma) {
		this.fechaFirma = fechaFirma;
	}
	public ArrayList<String> getRoles() {
		if (roles != null)
			return roles;
		else
			return new ArrayList<String>();
	}
	public void setRoles(ArrayList<String> roles) {
		this.roles = roles;
	}
	public ArrayList<PolicyResult> getPoliticas() {
		if (politicas != null)
			return politicas;
		else
			return new ArrayList<PolicyResult>();
	}
	public void setPoliticas(ArrayList<PolicyResult> politicas) {
		this.politicas = politicas;
	}

	public XAdESSchemas getEsquema() {
		return esquema;
	}
	public void setEsquema(XAdESSchemas esquema) {
		this.esquema = esquema;
	}
}
