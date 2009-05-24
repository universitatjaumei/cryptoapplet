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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Implementacion de java.security.spec.AlgorithmParameterSpec para la firma en IE
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class ParametrosFirma implements AlgorithmParameterSpec {
    
    private BigInteger numeroSerial;
    private String emisorDN;
    private String sujetoDN;
    private X509Certificate firmaCert ;
    private static ParametrosFirma paramFirmaInt = null;
    
    /**
     * devuelve un objeto de java.security.spec.AlgorithmParameterSpec para la firma IE
     * @param numeroSerial Numero de serie del certificado firmante
     * @param emisorDN Emisor del certificado
     * @return un objeto de java.security.spec.AlgorithmParameterSpec para la firma IE
     */
    public static AlgorithmParameterSpec getInstance(BigInteger numeroSerial, 
                                                                String emisorDN) {
        if (paramFirmaInt == null || 
                ! paramFirmaInt.getSerialNumber().equals(numeroSerial) ||
                ! paramFirmaInt.getSubjectDN().equals(emisorDN)){
            return new ParametrosFirma(numeroSerial, emisorDN);
        }else{
            return paramFirmaInt;
        }
    }
    
    /**
     * Crea una nueva instancia de ParametrosFirma
     * @param numeroSerial Número de serie del certificado firmante
     * @param emisorDN Emisor del certificado
     */
    protected ParametrosFirma(BigInteger numeroSerial, String emisorDN) {
        this.numeroSerial = numeroSerial;
        this.emisorDN = emisorDN;
    }

    /**
     * Obtiene la propiedad numeroSerial
     * @return valor de la propiedad numeroSerial
     */
    public BigInteger getSerialNumber() {
        return this.numeroSerial;
    }

    /**
     * Obtiene la propiedad emisorDN
     * @return valor de la propiedad emisorDN
     */
    public String getIssuerDN() {
        return this.emisorDN;
    }
    
    /**
     * Asigna el DN del certificado
     * @param subjectDN DN del certificado
     */
    public void setSubjectDN(String subjectDN) {
        this.sujetoDN = subjectDN;
    }
    
    /**
     * Obtiene la propiedad sujetoDN
     * @return Valor de la propiedad subjectDN
     */
    public String getSubjectDN() {
        return sujetoDN;
    }

    /**
     * Obtiene el certificado con el que se firmará
     * @return Devuelve la firma del certificado
     */
    public final X509Certificate getCertSign() {
        return firmaCert;
    }

    /**
     * Asigna el certificado con el que se firmará
     * @param firmaCert The certSign to set.
     */
    public final void setCertSign(X509Certificate firmaCert) {
        this.firmaCert = firmaCert;
    }
  
}
