package es.uji.security.crypto.mityc;

import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.ValidarFirmaXML;

public class MitycXAdESSignatureValidator 
{
	public boolean verify(byte[] data)
	{
		ResultadoValidacion result = null;
				
		try 
		{
			ValidarFirmaXML vXml = new ValidarFirmaXML();
			result = vXml.validar(data, null) ;
		} 
		catch(Exception e)
		{
			e.printStackTrace();
		}
				
		System.out.println(result.getLog());
		System.out.println(result.getNivelValido());
		
		return result.isValidate();
	}
}
