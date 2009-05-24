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

import java.math.BigInteger;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.tsp.GenTimeAccuracy;
import org.bouncycastle.tsp.TimeStampToken;

/** 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class TSValidacion {

	
	private boolean respuesta;
	private String fecha;
	private Date fechaDate;
	private X500Principal emisor;
	private GenTimeAccuracy precision;
	private long precisionLong;
	private BigInteger sello;
	private String selloAlg;
	private String firmaDigest;
	private String selloDigest;
	private TimeStampToken tst;
	
	public TSValidacion() {
		respuesta = false;
		fecha = null;
		fechaDate = null;
		emisor = null;
		precision = null;
		precisionLong = 0;
		sello = null;
		selloAlg = null;
		firmaDigest = null;
		selloDigest = null;
		tst = null;
	}


	public String getFecha() {
		return fecha;
	}


	public void setFecha(String fecha) {
		this.fecha = fecha;
	}


	public Date getFechaDate() {
		return fechaDate;
	}


	public void setFechaDate(Date fechaDate) {
		this.fechaDate = fechaDate;
	}


	public X500Principal getEmisor() {
		return emisor;
	}


	public void setEmisor(X500Principal emisor) {
		this.emisor = emisor;
	}


	public String getFirmaDigest() {
		return firmaDigest;
	}


	public void setFirmaDigest(String firmaDigest) {
		this.firmaDigest = firmaDigest;
	}


	public GenTimeAccuracy getPrecision() {
		return precision;
	}


	public void setPrecision(GenTimeAccuracy precision) {
		this.precision = precision;
	}


	public long getPrecisionLong() {
		return precisionLong;
	}


	public void setPrecisionLong(long precisionLong) {
		this.precisionLong = precisionLong;
	}


	public boolean isRespuesta() {
		return respuesta;
	}


	public void setRespuesta(boolean respuesta) {
		this.respuesta = respuesta;
	}


	public BigInteger getSello() {
		return sello;
	}


	public void setSello(BigInteger sello) {
		this.sello = sello;
	}


	public String getSelloAlg() {
		return selloAlg;
	}


	public void setSelloAlg(String selloAlg) {
		this.selloAlg = selloAlg;
	}


	public String getSelloDigest() {
		return selloDigest;
	}


	public void setSelloDigest(String selloDigest) {
		this.selloDigest = selloDigest;
	}


	public TimeStampToken getTst() {
		return tst;
	}


	public void setTst(TimeStampToken tst) {
		this.tst = tst;
	}
}
