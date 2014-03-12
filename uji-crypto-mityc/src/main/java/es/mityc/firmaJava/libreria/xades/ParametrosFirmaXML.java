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

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Parametros para la firma XML
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public final class ParametrosFirmaXML implements ConstantesXADES {
    
    private static ParametrosFirmaXML paramFirma =null ;
    private BigInteger numeroSerial = null ;
    private String emisorDN = null ;
    private String modoFirma = CADENA_VACIA;
    private String perfilUsuario = CADENA_VACIA;
    public boolean verificado = false ;
    
    /**
     * Crea una nueva instancia de ParametrosFirmaXML
     */
    private ParametrosFirmaXML() {
        super();
    }

    /**
     * Devuelve un objeto de la clase , nuevo si no existia o el creado anteriormente 
     * en caso de existir
     * @return Objeto de la clase, en cache o nuevo
     */
    public static ParametrosFirmaXML getInstance(){
        if(paramFirma == null ){
            ParametrosFirmaXML signParamTemp =  new ParametrosFirmaXML();
            paramFirma = signParamTemp;
        }
        return paramFirma;
    }
    
    /**
     * Asigna el número de serie del certificado firmante
     * @param numeroSerial Número de serie
     */
    public void setSerialNumber(BigInteger numeroSerial) {
        this.numeroSerial = numeroSerial;
    }
    
    /**
     * Devuelve el número de serie del certificado firmante
     * @return número de serie del certificado firmante
     */
    public BigInteger getSerialNumber() {
        return numeroSerial;
    }
    
    /**
     * Asigna el emisor del certificado firmante
     * @param emisorDN emisor del certificado firmante
     */
    public void setIssuerDN(String emisorDN) {
        this.emisorDN = emisorDN;
    }

    /**
     * Devuelve el emisor del certificado firmante
     * @return emisor del certificado firmante
     */
    public String getIssuerDN() {
        return emisorDN;
    }
    
    /**
     * Devuelve el modo de firma seleccionado
     * @return devuelve el modo de firma
     */
    public final String getModeSign() {
        return modoFirma;
    }
    
    /**
     * Asigna el modo de firma seleccionado
     * @param modeSign el modo de firma seleccionado
     */
    public final void setModeSign(String modeSign) {
        this.modoFirma = modeSign;
    }
    
    /**
     * Devuelve el perfil del usuario, ruta al almacen de firefox
     * @return perfil del usuario, ruta al almacén de firefox
     */
    public final String getPerfilUsuario() {
        return perfilUsuario;
    }
    
    /**
     * Asigna perfil del usuario, ruta al almacen de firefox
     * @param perfilUsuario perfil del usuario, ruta al almacén de firefox
     */
    public final void setPerfilUsuario(String perfilUsuario) {
        this.perfilUsuario = perfilUsuario;
    }
    
    /**
     * Inicializa el objeto en cache de ParametrosFirmaXML.
     * Se utiliza para eliminar la configuración de los parámetros en la cache.
     */
    
    public static final void initialize(){
        paramFirma = null ;
    }

}
