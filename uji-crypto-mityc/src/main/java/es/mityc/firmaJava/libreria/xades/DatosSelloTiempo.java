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

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.tsp.TimeStampToken;

import es.mityc.firmaJava.trust.ConfianzaEnum;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class DatosSelloTiempo {
	
	private Date fecha = null;
	private X500Principal emisor = null;
	private String algoritmo = null;
	private Long precision = null;
	private TipoSellosTiempo tipoSello = null;
	private TimeStampToken tst = null;
	private ConfianzaEnum esCertConfianza = ConfianzaEnum.NO_REVISADO;
	
	public DatosSelloTiempo() {}
	
	/**
	 * Almacena información referente al sello de tiempo de una firma
	 * 
	 * @param java.util.Date fecha  .- Fecha del sello de tiempo
	 * @param String emisor     	.- Emisor del sello de tiempo 
	 * @param String algoritmo  	.- Algoritmo de calculo del hash del sello
	 * @param TipoSellosTiempo		.- Tipo de sello para la firma XAdES-X
	 * @param TimeStampToken        .- El objeto que almacena el sello de tiempo  
	 * @param esCertConfianza       .- Indica si el certificado de la TSA es considerado de confianza
	 */
	public DatosSelloTiempo(Date fecha,
			X500Principal emisor,
			String algoritmo,
			Long precision,
			TipoSellosTiempo tipoSello,
			TimeStampToken tst,
			ConfianzaEnum esCertconfianza) {
		
		this.fecha = fecha;
		this.emisor = emisor;
		this.algoritmo = algoritmo;
		this.precision = precision;
		this.tipoSello = tipoSello;
		this.tst = tst;
		this.esCertConfianza = esCertconfianza;
	}
	
	public String getAlgoritmo() {
		return algoritmo;
	}
	public void setAlgoritmo(String algoritmo) {
		this.algoritmo = algoritmo;
	}
	public X500Principal getEmisor() {
		return emisor;
	}
	public void setEmisor(X500Principal emisor) {
		this.emisor = emisor;
	}
	public Date getFecha() {
		return fecha;
	}
	public void setFecha(Date fecha) {
		this.fecha = fecha;
	}
	public Long getPrecision() {
		return precision;
	}
	public void setPrecision(Long precision) {
		this.precision = precision;
	}
	public TipoSellosTiempo getTipoSello() {
		return tipoSello;
	}
	public void setTipoSello(TipoSellosTiempo tipoSello) {
		this.tipoSello = tipoSello;
	}
	public TimeStampToken getTst() {
		return tst;
	}
	public void setTst(TimeStampToken tst) {
		this.tst = tst;
	}
	public ConfianzaEnum esCertConfianza() {
		return esCertConfianza;
	}
	public void setEsCertConfianza(ConfianzaEnum esCertConfianza) {
		this.esCertConfianza = esCertConfianza;
	}
}
