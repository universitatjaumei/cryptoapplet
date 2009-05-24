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

package es.mityc.firmaJava.libreria.utilidades;

import java.util.Locale;
import java.util.ResourceBundle;

import es.mityc.firmaJava.libreria.ConstantesXADES;


/**
 * Clase que permite la internacionalización de las cadenas de texto de la aplicación
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class I18n implements ConstantesXADES{
	
    private static Locale locale = new Locale(DEFAULT_LOCALE,DEFAULT_LOCALE.toUpperCase());

    
    /**
     * Obtiene el valor de una cadena definida para el idioma por defecto configurado
     * @param clave Clave que identifica la cadena de texto
     * @return cadena traducida para un determinado idioma
     */
    public static String getResource(String clave)
    {
        return getResource(clave, locale) ;
    }
    
    
    /**
     * Obtiene el valor de una cadena definida para el idioma pasado por parametro en el Locale
     * @param clave Clave que identifica la cadena de texto
     * @param locale Locale del idioma del cual queremos la traduccion
     * @return cadena traducida para un determinado idioma
     */
    public static String getResource(String clave, Locale locale)
    {
        return ResourceBundle.getBundle(LOCALE_FILES, locale).getString(clave) ;
    }
    
    
    /**
     * Obtiene el Locale que se utiliza en ese momento
     * @return Locale que se utiliza en ese momento
     */
    public static Locale getLocale() 
    {
        return locale;
    }
    
    
    /**
     * Asigna el Locale que se utilizara en las traducciones
     * @param locale Locale que se utilizara en las traducciones
     */
//    public static void setLocale(Locale _locale) 
//    {
//        locale = _locale;
//    }
//    
    
    /**
     * Asigna el Locale que se utilizara en las traducciones
     * @param pais Pais
     * @param dialecto Dialecto del idioma
     */
    public static void setLocale(String pais, String dialecto) 
    {
        locale = new Locale(pais, dialecto);
    }

}
