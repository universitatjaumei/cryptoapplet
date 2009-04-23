package es.uji.dsign.applet2.junit;

import es.uji.dsign.applet2.*;


public class DesktopApplicationTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try{
			byte[] b= new byte[100];								
			AppHandler apph= new AppHandler(null);
			MainWindow mw= new MainWindow(apph);		
		}
		catch (Exception ex){
		 	ex.printStackTrace();
		}
	}

}
