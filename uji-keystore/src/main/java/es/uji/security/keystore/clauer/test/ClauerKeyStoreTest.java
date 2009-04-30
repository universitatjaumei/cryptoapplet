package es.uji.security.keystore.clauer.test;

import es.uji.security.keystore.clauer.ClauerKeyStore;

public class ClauerKeyStoreTest
{
	public static void main(String[] args)
	{
		try
		{
			new ClauerKeyStore();
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}
}
