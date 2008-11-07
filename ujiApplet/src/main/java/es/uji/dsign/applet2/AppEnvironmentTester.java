package es.uji.dsign.applet2;

import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.event.AdjustmentEvent;
import java.awt.event.AdjustmentListener;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class AppEnvironmentTester extends Thread {
	
	private JFrame _jf= new JFrame();
	private AppHandler _apph;
	private JScrollPane _jsp  = new JScrollPane();
	private JTextArea _jta= new JTextArea();
	private String appletTag;
 	
	
	
	private void caption(String str){
		_jta.append("\nTesting: " + str + "\n");	
	}
	
	private void info(String str){
		_jta.append("    [INFO]  " + str + "\n");	
	}
	
	private void  warn(String str){
		_jta.append("    [WARN]  " + str + "\n");	
	}
	
	private void  error(String str){
		_jta.append("    [ERROR] " + str + "\n");	
	}
	
	private void testConnect(URL url){
		try{
			HttpURLConnection urlConn = (HttpURLConnection) url.openConnection();

			urlConn.setConnectTimeout(10000);
			urlConn.setReadTimeout(10000);

			urlConn.setRequestMethod("GET");
			urlConn.setDoOutput(true);
			urlConn.setDoInput(true);

			if (urlConn.getResponseCode() != HttpURLConnection.HTTP_OK){
				error("Connecting with " + url.toString() +  " . Error= " + urlConn.getResponseCode());
			}
			else{ 
				info("Connection to " + url.toString() + " OK");
			}
		}
		catch (Exception e){
			error("Connection to " + url.toString() + " has thrown Exception: "  + e.getMessage());
		}	
	}
	
	private void testJavaVersion(){
		caption("Version");
		String version= _apph.getSignatureApplet().getJavaVersion();
		info("Got java version: " + version);
		if (!(version.startsWith("1.6") || version.startsWith("1.5")
				|| version.startsWith("1.7"))){
				
			error("Java version must be >= 1.5");
		}
	}
	
	private void testAppletTag(){
		caption("Applet Tag");
		URL codebase= _apph.getSignatureApplet().getCodeBase();
				
		info("Got codebase: " + codebase.toString());
		testConnect(codebase);
		
		String loweredTag= this.appletTag.toLowerCase();

		int ini= loweredTag.indexOf("mayscript");
		if (ini ==-1 ){ 
			 warn("mayscript tag not found, the applet could not work on firefox.");
			 return; 
		}
		
		ini= loweredTag.indexOf("archive");
		if (ini ==-1 ){ 
			 error("Cannot locate archive attribute in applet tag.");
			 return; 
		}
		
		int i= loweredTag.indexOf("\"",ini);
		
		if (i==-1)
			i= loweredTag.indexOf("'",ini);
		
		if (i==-1){
			error("Unable to find the stating \" or ' at archive attribute.");
			return;
		}
		
		int end= loweredTag.indexOf("\"", i+1);
		if (end == -1) 
				end= loweredTag.indexOf("'", i+1);
		if (end==-1){
			error("Unable to find the closing \" or ' at archive attribute.");
			return;
		}
		
		String aux= this.appletTag.substring(ini,end);
		aux= aux.replaceFirst("archive[ ]*=[ ]*['\"]", "");
		aux= aux.replaceAll("[\r\n]", "");
		
		String items[]= aux.split(",");
		for (i=0; i<items.length; i++){
			try {
				testConnect(new URL(codebase.toString() + items[i]));
			} catch (MalformedURLException e) {
				error("Cannot check " + codebase.toString() + items[i] + " has thrown MalformedURLException");
			}
		}
	}

	private void testSignatureOutputFormat(){
		caption("SignatureOutputFormat");
		
		String format= _apph.getSignatureOutputFormat();
		String lowerTag= this.appletTag.toLowerCase();
		
		info("signatureOutputFormat set to: "  + format);
		
		if (_apph.getformatImplMap().get(format)==null)
		{
			error("Invalid output format " + format);
			return; 
		}
		
		
		//Check dependencies. 
		//First the generic ones: 
		//bcprov.jar, jakarta-log4j.jar
		if ( lowerTag.indexOf("bcprov") == -1 ){
			warn("bcprov.* not found and it is needed by all signature formats, make sure you have included it with another name.");
		}
		
		if ( lowerTag.indexOf("jakarta") == -1 ){
			warn("jakarta.* not found and it is needed by all signature formats, make sure you have included it with another name.");
		}
		
		if (format.equals("CMS") | format.equals("CMS_HASH")){
			if ( lowerTag.indexOf("bcmail") == -1 ){
				warn("bcmail.* not found and it is needed by " + format + " singature format");
			}
		}
		else if (format.equals("XADES") | format.equals("XADES_COSIGN")){
			//String deps[]= {};
		}
		else if (format.equals("PDF")){
			if ( lowerTag.indexOf("itext") == -1 ){
				warn("itext.* not found and it is needed by " + format + " singature format");
			}
		}
	}
	
	private void testCertificates(){
		
		
	}
	
	private void testClauer(){
		
	}
	
	private void testKeyStores(){
		
			
	}
	
	public void setAppletHandler(AppHandler apph){
		this._apph= apph;
	}
	
	public void setAppletTag(String appletTag){
		this.appletTag= appletTag; 
	} 
	
	public void run(){
		Toolkit toolkit = Toolkit.getDefaultToolkit();
		int _height = toolkit.getScreenSize().height;
		int _width = toolkit.getScreenSize().width;
		
		_jta.setEditable(false);
		_jta.append("Resultados de los tests:\n");
		
		_jsp.setBounds(new Rectangle(9, 28, 558, 173));
		_jsp.setViewportView(_jta);
		_jsp.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
		
		_jsp.getVerticalScrollBar().addAdjustmentListener(new AdjustmentListener(){
			public void adjustmentValueChanged(AdjustmentEvent e){
			_jta.select(_jta.getHeight()+1000,0);
		}});
		
		_jf.setLocation(_width / 2 - 582 / 2, _height / 2 - 518 / 2);
		
		_jf.setTitle("Application Test");
		_jf.setSize(new Dimension(700,400));
		//_jf.setBounds(new Rectangle(9, 28, 558, 173));
		
		_jf.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		_jf.setContentPane(_jsp);
		_jf.setVisible(true);
		
		// Lets go with the tests
		testJavaVersion();
		testAppletTag();
		testSignatureOutputFormat();
		
	}
}
