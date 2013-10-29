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

package es.mityc.firmaJava.configuracion;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.MissingResourceException;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Esta clase carga la configuracion almacenada en el fichero 
 * SignXML.properties o si este no existe cargar la configuracion por defecto
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0 beta
 */

public class Configuracion implements  Serializable, ConstantesConfiguracion
{
	private static final long serialVersionUID = 1L;

	static Log log = LogFactory.getLog(Configuracion.class);
    
    protected HashMap<String, String> configuracion = new HashMap<String, String>();
    
    private static boolean chequeaPermiteFicheroExterno() {
    	boolean resultado = false;
    	try {
	    	ResourceBundle propiedadesPorDefecto = ResourceBundle.getBundle(FICHERO_RESOURCE);
	    	String ficherExt = propiedadesPorDefecto.getString(CONFIG_EXT);
	    	resultado = isTrue(ficherExt);
    	} catch (MissingResourceException ex) {
    		// En caso de que no exista la clave en el SignXML por defecto, se recupera el externo 
    		resultado = true;
    	}
    	return resultado;
    }
    
    private static String getNombreFicheroExterno() {
    	String resultado = FICHERO_PROPIEDADES;
    	try {
	    	ResourceBundle propiedadesPorDefecto = ResourceBundle.getBundle(FICHERO_RESOURCE);
	    	resultado = propiedadesPorDefecto.getString(CONFIG_EXT_FILE);
    	} catch (MissingResourceException ex) {
    	}
    	return resultado;
    }

    public static String getNombreDirExterno() {
    	String resultado = "";
    	try {
	    	ResourceBundle propiedadesPorDefecto = ResourceBundle.getBundle(FICHERO_RESOURCE);
	    	resultado = propiedadesPorDefecto.getString(CONFIG_EXT_DIR);
    	} catch (MissingResourceException ex) {
    	}
    	return resultado;
    }

    /**
     * Este método carga la configuración definida en el fichero SignXML.properties
     */
    public void cargarConfiguracion() 
    {
    	
    	Enumeration<Object> enuClaves = null;
        // Intenta cargar el fichero de propiedades externo si lo tiene permitido
    	if (chequeaPermiteFicheroExterno()) {
            Properties propiedades = new Properties();
            FileInputStream fis = null;
			try {
			    File fichero = new File(System.getProperty(USER_HOME) + File.separator + getNombreDirExterno(), getNombreFicheroExterno());
				fis = new FileInputStream(fichero); 
				propiedades.load(fis);
				configuracion = new HashMap<String, String>();
			    enuClaves = propiedades.keys();
			    boolean hasNext = enuClaves.hasMoreElements();
			    while(hasNext) {
			       String clave = (String)enuClaves.nextElement();
			       hasNext = enuClaves.hasMoreElements();
			       configuracion.put(clave, propiedades.getProperty(clave));
			    }
			} catch (FileNotFoundException e) {
				cargarConfiguracionPorDefecto();
				
			} catch (IOException e) {
				cargarConfiguracionPorDefecto();
			}
			
			finally{
				try {
					if (fis !=null){
						fis.close();
					}
				} catch (IOException e) {
					log.error(e);
				}
			}
    	}
    	else {
    		cargarConfiguracionPorDefecto();
    	}
        
    }
    
    private void cargarConfiguracionPorDefecto() {
    	
    	log.debug (CARGA_CONFIGURACION_DEFECTO);
    	Enumeration<String> enuClaves = null;
    	ResourceBundle propiedadesPorDefecto = ResourceBundle.getBundle(FICHERO_RESOURCE);
        configuracion = new HashMap<String, String>();
        enuClaves = propiedadesPorDefecto.getKeys();
        boolean hasNext = enuClaves.hasMoreElements();
        while(hasNext)
        {
            String clave = enuClaves.nextElement();
            hasNext = enuClaves.hasMoreElements();
            configuracion.put(clave, propiedadesPorDefecto.getString(clave));
        }
		
	}

	/**
     * Este método guarda la configuración en el fichero SignXML.properties
     * @throws IOException 
     */
    public void guardarConfiguracion() throws IOException 
    {	
        StringBuffer paraGrabar = new StringBuffer();
	    String linea;

    	// La configuración siempre se guarda en un fichero externo
	    File dir = new File(System.getProperty(USER_HOME) + File.separator + getNombreDirExterno());
	    if ((!dir.exists()) || (!dir.isDirectory())) {
	    	if (!dir.mkdir())
	    		return;
	    }
		File fichero = new File(dir, getNombreFicheroExterno());
		log.trace("Salva fichero de configuración en: " + fichero.getAbsolutePath());
		if (!fichero.exists())
		{
			// Si el fichero externo no existe se crea fuera un copia
			// del fichero almacenado dentro del jar
			InputStream fis = getClass().getResourceAsStream(FICHERO_PROPIEDADES);
			BufferedInputStream bis = new BufferedInputStream(fis);
			FileOutputStream fos = new FileOutputStream(fichero);
			BufferedOutputStream bos = new BufferedOutputStream(fos);
            int length = bis.available();	  
            byte[] datos= new byte[length] ;
            bis.read(datos) ;
			bos.write(datos);
			bos.flush();
			bos.close();
			bis.close();
		}
		// AppPerfect: Falso positivo
	    BufferedReader propiedades = new BufferedReader(new FileReader(fichero));
	    
	    
	    linea = propiedades.readLine();
	    while(linea != null) {
	    	StringTokenizer token = new StringTokenizer(linea, IGUAL);
	    	if (token.hasMoreTokens())
	    	{
				String clave =token.nextToken().trim();
				if (configuracion.containsKey(clave))
				{
					paraGrabar.append(clave);
					paraGrabar.append(IGUAL_ESPACIADO);
					paraGrabar.append(getValor(clave));
					paraGrabar.append(CRLF);
				}
				else
				{
					paraGrabar.append(linea);
					paraGrabar.append(CRLF);
								    		
				}
	    	}
	    	else
	    		paraGrabar.append(CRLF);
	    	linea = propiedades.readLine();
	    }
	    propiedades.close();	   
	    
	    //AppPerfect: Falso positivo
	    FileWriter fw = new FileWriter(fichero);
	    BufferedWriter bw = new BufferedWriter(fw);
	    bw.write(String.valueOf(paraGrabar));
	    bw.flush();
	    bw.close();
	    
    }
    
    /**
     * Obtiene el tipo de almacen de certificados configurado
     * 
     * @return enumeración con el tipo de almacen configurado, IExplorer si no hay indicado ninguno
     * @see es.mityc.firmaJava.configuracion.EnumAlmacenCertificados
     */
    public EnumAlmacenCertificados getAlmacenCertificados() {
    	EnumAlmacenCertificados almacen = EnumAlmacenCertificados.ALMACEN_EXPLORER;
    	String valor = (String)configuracion.get(CFG_ALMACEN);
    	valor = (valor == null) ? CADENA_VACIA : valor.toUpperCase().trim();
    	if (CFG_ALMACEN_EXPLORER.equalsIgnoreCase(valor)) {
    		almacen = EnumAlmacenCertificados.ALMACEN_EXPLORER;
    	} else if (CFG_ALMACEN_MOZILLA.equalsIgnoreCase(valor)) {
    		almacen = EnumAlmacenCertificados.ALMACEN_MOZILLA;
    	}
    	return almacen;
    }
 
   	/**
   	 * Obtiene el formato de firma configurado (Parametro 'FormatoXades')
	 * @return
	 */
   public EnumFormatoFirma getFormatoXades() {

	    EnumFormatoFirma formatoXades = EnumFormatoFirma.XAdES_BES;
	    
   		String valor = (String)configuracion.get(CFG_FORMATO_XADES);
   		if (isEmpty(valor)) {
   			log.warn(NO_FORMATO_XADES);
   			formatoXades = EnumFormatoFirma.XAdES_BES;
   		}
   		else {
   			valor = valor.toUpperCase().trim();

   			if (valor.equals (CFG_XADES_BES.toUpperCase().trim())) 
	   			formatoXades = EnumFormatoFirma.XAdES_BES;
   			else if (valor.equals (CFG_XADES_T.toUpperCase().trim())) 
	   			formatoXades = EnumFormatoFirma.XAdES_T;
   			else if (valor.equals (CFG_XADES_C.toUpperCase().trim())) 
	   			formatoXades = EnumFormatoFirma.XAdES_C;
   			else if (valor.equals (CFG_XADES_X.toUpperCase().trim())) 
	   			formatoXades = EnumFormatoFirma.XAdES_X;
   			else if (valor.equals (CFG_XADES_XL.toUpperCase().trim())) 
	   			formatoXades = EnumFormatoFirma.XAdES_XL;
   		}
   		
   		return formatoXades;
   }
   public void setFormatoXades(EnumFormatoFirma valor) {
	   String clave = CFG_FORMATO_XADES;
	   String sValor = CFG_XADES_BES;
	   switch (valor) {
	   	case XMLSignature:
	   		sValor = CFG_XADES_BES;
	   		break;
	   	case XAdES_T:
	   		sValor = CFG_XADES_T;
	   		break;
	   	case XAdES_C:
	   		sValor = CFG_XADES_C;
	   		break;
	   	case XAdES_X:
	   		sValor = CFG_XADES_X;
	   		break;
	   	case XAdES_XL:
	   		sValor = CFG_XADES_XL;
	   		break;
	   	default:
	   		sValor = CFG_XADES_BES;
   			break;
	   }
	   setValor(clave, sValor);
   }
    
    /**
     * Este método devuelve el valor especificado en el fichero de propiedades
     * para la clave pasada como parámetro. Si en dicho fichero no se encuentra
     * ningún valor para la clave, se devuelve un valor definido por defecto.
     * @param clave Nombre de la clave
     * @return valor Valor de la clave
     */
    public String getValor(String clave) {
    	String valor = (String)configuracion.get(clave);
    	if((valor == null || valor.equals(CADENA_VACIA)) && clave != null)
    	{
    		if(clave.equals(XMLNS))
    			valor = VALOR_XML_SN;
    		else if(clave.equals(XML_XADES_NS))
    			valor = VALOR_XML_XADES_NS;
    		else if(clave.equals(PKCS7))
    			valor = VALOR_PKCS7;
    		else 
    			if(clave.equals(IS_PROXY))
    			valor = VALOR_IS_PROXY;
    		else if(clave.equals(VALIDATE_OCSP))
    			valor = VALOR_VALIDATE_OCSP;
    		else if(clave.equals(SAVE_SIGN))
    			valor = VALOR_SAVE_SIGN;
    		else 
    			if(clave.equals(XML_DSIG_SCHEMA))
    			valor = VALOR_XML_DSIG_SCHEMA;
    		else if(clave.equals(XADES_SCHEMA))
    			valor = VALOR_XADES_SCHEMA;
    		else if(clave.equals(LOCALE))
    			valor = VALOR_LOCALE;
    		else if(clave.equals(ENCODING_XML))
    			valor = VALOR_ENCODING_XML;
    	}   	
    	return valor;
    }
    /**
     * Se escribe los valores de configuración
     * @param clave Nombre de la clave
     * @param valor Valor de la clave
     */
    public void setValor(String clave, String valor) {
        configuracion.put(clave,valor) ;
    }
    
    /**
     * Convierte el valor de configuración en formato cadena
     * @return cadena Valor convertido en cadena
     */
    public String toString()
    {
        StringBuffer cadena = new StringBuffer();
        Iterator<String> it = configuracion.keySet().iterator();
        boolean hasNext = it.hasNext();
        while(hasNext)
        {
            String claveTemporal = it.next() ;
            hasNext = it.hasNext();
            cadena.append(KEY);
            cadena.append(claveTemporal);
            cadena.append(VALUE);
            cadena.append(configuracion.get(claveTemporal));
            cadena.append(CRLF);
        }
        return String.valueOf(cadena);
    }
    
    /**
     * Invoca el valor de una clave booleana y devuelve su estado
     * @param clave Nombre de la clave a comparar
     * @return Estado de la clave
     */
    public boolean comparar (String clave) {
    	String parametro = getValor(clave.trim());
    	if(parametro == null)
			log.debug(ERROR_DOS_PUNTOS + clave + IGUAL_NULL);
    	
		return isTrue(parametro);
    }
 	public static boolean isTrue (String parametro) {
 		if(parametro == null) return false;
 		
 		return (
 				parametro.toLowerCase().trim().equals(SI_MINUSCULA) || 
 				parametro.toLowerCase().trim().equals(YES_MINUSCULA)
 				);
	    
    }

   
    /**
     * Invoca el valor de tipo entero y devuelve su valor. Si no encuentra la clave devuelve -1.
     * @param clave Nombre de la clave a comparar
     * @return Valor de la clave.
     */
    public int getInteger (String clave)  //    throws NumberFormatException
    {
    	int number = -1;
    	String valor = (String)configuracion.get(clave);
    	if((valor == null || valor.equals(CADENA_VACIA)) && clave != null) {
    		try {
    			number = Integer.parseInt(valor,10);
    		} catch (NumberFormatException e) {
    			log.debug(ERROR_DOS_PUNTOS + clave + e.getMessage());
//    			throw new NumberFormatException (e.getMessage());
    		}
    	}
    	return number;
    		
    }    

    /**
     * Comprueba si el parametro indicado es una cadena vacia.
     * @param valor a comprobar
     * @return true si es una cadena vacia o nulo. False en otro caso.
     */
    public static boolean isEmpty (String valor) {
    	 return (valor == null || valor.trim().equals(CADENA_VACIA));
    }
}


