package es.uji.dsign.applet2;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.security.PrivateKey;

import javax.net.ssl.SSLHandshakeException;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.tree.DefaultMutableTreeNode;

import es.uji.dsign.applet2.Exceptions.SignatureAppletException;
import es.uji.dsign.crypto.ISignFormatProvider;
import es.uji.dsign.crypto.X509CertificateHandler;
import es.uji.dsign.crypto.XAdESSignatureFactory;
import es.uji.dsign.crypto.keystore.IKeyStoreHelper;
import es.uji.dsign.util.Base64;
import es.uji.dsign.util.HexEncoder;
import es.uji.dsign.util.i18n.LabelManager;
import es.uji.dsign.applet2.io.InputParams;
import es.uji.dsign.applet2.io.OutputParams;


public class SignatureThread extends Thread
{
	private MainWindow _mw= null;
	private int _end_percent= 0;
	private int _ini_percent= 0;
	private boolean hideWindow;
	private Method callback;
	private boolean showSignatureOk;

	public SignatureThread(String str)
	{
		super(str);
	}

	public void setPercentRange(int ini_percent, int end_percent){
		this._ini_percent= ini_percent;
		this._end_percent= end_percent;
	} 

	public void setHideWindowOnEnd(boolean hideWindow){
		this.hideWindow= hideWindow;
	}


	public void setCallbackMethod(Method m){
		callback= m;
	}

	public void run()
	{

		IKeyStoreHelper iksh;
		guiInitialize();
		JLabel infoLabelField= _mw.getInformationLabelField();
		
		infoLabelField.setText(LabelManager.get("COMPUTING_SIGNATURE"));
		
		int inc= (this._end_percent - this._ini_percent)/10;

		try{
			X509CertificateHandler selectedNode = (X509CertificateHandler) ((DefaultMutableTreeNode) _mw.jTree.getLastSelectedPathComponent()).getUserObject();

			if (!selectedNode.isDigitalSignatureCertificate() && !selectedNode.isNonRepudiationCertificate())
			{
				infoLabelField.setText(LabelManager.get("ERROR_CERTIFICATE_USE"));
				guiFinalize(false);
				showSignatureOk=false;
				throw new SignatureAppletException("Invalid Key usage.");
			} 

			iksh= selectedNode.getKeyStore();
			if (iksh != null){	
				try
				{
					iksh.load(_mw.getPasswordTextField().getText().toCharArray());
					
					//TODO: Research: Some problems of codification with 1.6 jvm and 
					//      JPasswordField.
					//iksh.load(_mw.getPasswordField().getPassword());
				}
				catch (Exception e)
				{
					ByteArrayOutputStream os = new ByteArrayOutputStream();
					PrintStream ps = new PrintStream(os);
					e.printStackTrace(ps);
					String stk = new String(os.toByteArray()).toLowerCase();
					if ( stk.indexOf("incorrect") > -1 ){
						infoLabelField.setText(LabelManager.get("ERROR_INCORRECT_PWD"));
						showSignatureOk=false;
						guiFinalize(false);
						throw new SignatureAppletException("Incorrect Password.");
					}
					else
						infoLabelField.setText("Unexpected error!!!");
					e.printStackTrace();
				}
				System.out.println("Certificate Alias: " +  iksh.getAliasFromCertificate(selectedNode.getCertificate()));
			}
			else{
				infoLabelField.setText(LabelManager.get("ERR_GET_KEYSTORE"));
				guiFinalize(false);
				showSignatureOk=false;
				throw new SignatureAppletException("Unable to guess the keystore.");
			}

			_mw.getGlobalProgressBar().setValue(_ini_percent + inc);

			// Instanciamos el tipo de clase de gestión de parámetros de E/S:
			// Applet, URL, etc
			//Class sip = Class.forName(_mw._aph.getInputParams());

			InputParams inputParams = (InputParams)_mw._aph.getInput(); //sip.newInstance();
			//Class sop = Class.forName(_mw._aph.getOutputParams());

			_mw.getGlobalProgressBar().setValue(_ini_percent + 2*inc);

			OutputParams outputParams = (OutputParams) _mw.getAppHandler().getOutputParams();//sop.newInstance();

			_mw.getGlobalProgressBar().setValue(_ini_percent + 3*inc);
			// Instanciamos el formateador de firma: CMS, XAdES, etc
			Class sf = Class.forName(_mw.getAppHandler().getSignFormat());
			ISignFormatProvider signer = (ISignFormatProvider) sf.newInstance();

			if (_mw.getAppHandler().getSignFormat().equals("es.uji.dsign.crypto.XAdESSignatureFactory"))
			{
				String sr= (_mw.getAppHandler().getSignerRole() != null)? _mw.getAppHandler().getSignerRole(): "UNSET";
				XAdESSignatureFactory xs= (XAdESSignatureFactory) signer;
				xs.setSignerRole(sr);
			}

			_mw.getGlobalProgressBar().setValue(_ini_percent + 4*inc);
			if (_mw.jTree.getLastSelectedPathComponent() != null)
			{
				X509CertificateHandler xcert;
				try{
					xcert = (X509CertificateHandler) ((DefaultMutableTreeNode) _mw.jTree.getLastSelectedPathComponent()).getUserObject();
				}
				catch (NullPointerException e){
					infoLabelField.setText(LabelManager.get("ERROR_CERTIFICATE_NOT_SELECTED"));
					showSignatureOk= false;
					guiFinalize(false);
					return;

				}
				if (xcert.isDigitalSignatureCertificate() || 
						(xcert.isEmailProtectionCertificate() &&
								_mw.getAppHandler().getSignFormat().equals("es.uji.dsign.crypto.CMSSignatureFactory")));
				{
					ByteArrayOutputStream ot = new ByteArrayOutputStream();

					byte[] in;

					String encoding= _mw.getAppHandler().getEncoding() != null ? _mw._aph.getEncoding() : "plain";


					_mw.getGlobalProgressBar().setValue(_ini_percent + 5*inc);
					if ( encoding.toLowerCase().equals("hex") ){
						HexEncoder h= new HexEncoder();
						h.decode(new String(inputParams.getSignData()), ot);
						in= ot.toByteArray();
					}
					else if ( encoding.toLowerCase().equals("base64") ){
						in= Base64.decode(inputParams.getSignData());
					}
					else{
						in= inputParams.getSignData(); //_mw._aph.inputData;	
					}

					if (_mw.isShowSignatureEnabled()){
						int sel=JOptionPane.showConfirmDialog(_mw.getMainFrame(),_mw.getShowDataScrollPane(in), LabelManager.get("LABEL_SHOW_DATA_WINDOW") , JOptionPane.OK_CANCEL_OPTION);
						if ( sel != JOptionPane.OK_OPTION ){
							_mw.getAppHandler().callJavaScriptCallbackFunction(_mw.getAppHandler().getJsSignCancel(), new String[] {});
							showSignatureOk= false;
							guiFinalize(true);
							return;
						}
					}
					
					byte[] sig= null;

					_mw.getGlobalProgressBar().setValue(_ini_percent + 6*inc);

					IKeyStoreHelper kAux= xcert.getKeyStore();
					sig= signer.formatSignature( in, xcert.getCertificate(), (PrivateKey) kAux.getKey(xcert.getAlias()),kAux.getProvider());

					if ( sig == null )
					{
						infoLabelField.setText(LabelManager.get("ERROR_COMPUTING_SIGNATURE") +": " + signer.getError());
						showSignatureOk= false;
						guiFinalize(false);
						_mw.getAppHandler().getInputParams().flush();
						return;
					}

					_mw.getGlobalProgressBar().setValue(_ini_percent + 7*inc);
					if ( sig != null )	
						outputParams.setSignData(sig);
					else 	
						System.out.println("ERROR!!! al calcular la firma");
				}
				_mw.getGlobalProgressBar().setValue(_ini_percent + 8*inc);
			}
			_mw.getGlobalProgressBar().setValue(_ini_percent + 10*inc);


			guiFinalize(hideWindow);

			callback.invoke(null, null);
		}
		catch (SSLHandshakeException e){
			infoLabelField.setText(LabelManager.get("ERROR_SSL") +": " + e.getMessage());
			showSignatureOk= false;
			e.printStackTrace();
			try {
				guiFinalize(false);
			} catch (Exception e1) {
				infoLabelField.setText(LabelManager.get("ERROR_CANNOT_CLOSE_WINDOW"));
				e1.printStackTrace();
			}		
		}
		catch(ClassCastException e){
			e.printStackTrace();
			infoLabelField.setText(LabelManager.get("ERROR_CERTIFICATE_NOT_SELECTED"));
			try {
				showSignatureOk= false;
				guiFinalize(false);
			} catch (Exception e1) {
				infoLabelField.setText(LabelManager.get("ERROR_CANNOT_CLOSE_WINDOW"));
			}
		}
		catch(NullPointerException e){
			e.printStackTrace();
			infoLabelField.setText(LabelManager.get("ERROR_COMPUTING_SIGNATURE") + ": "+ e.getMessage());
			try {
				showSignatureOk= false;
				guiFinalize(false);
			} catch (Exception e1) {
				infoLabelField.setText(LabelManager.get("ERROR_CANNOT_CLOSE_WINDOW"));
			}
		}
		catch(IOException e){
			infoLabelField.setText(LabelManager.get("ERROR_INPUT_SOURCE"));
			showSignatureOk= false;
			e.printStackTrace();
			try {
				guiFinalize(true);
			} catch (Exception e1) {
				infoLabelField.setText(LabelManager.get("ERROR_CANNOT_CLOSE_WINDOW"));
				e1.printStackTrace();
			}
		}
		catch(Exception e){
			
			e.printStackTrace();
			
			if (e.getMessage() != null && e.getMessage().indexOf("Incorrect Password") != -1 ){
				infoLabelField.setText(LabelManager.get("ERROR_INCORRECT_PASSWORD"));
				showSignatureOk= false;
				try {
					guiFinalize(false);
				} catch (Exception e1) {
					infoLabelField.setText(LabelManager.get("ERROR_CANNOT_CLOSE_WINDOW"));
					e1.printStackTrace();
				}		
			}
			else{
				infoLabelField.setText(LabelManager.get("ERROR_COMPUTING_SIGNATURE") +": " + e.getMessage());
				showSignatureOk= false;
				e.printStackTrace();
				try {
					guiFinalize(false);
				} catch (Exception e1) {
					infoLabelField.setText(LabelManager.get("ERROR_CANNOT_CLOSE_WINDOW"));
					e1.printStackTrace();
				}
				_mw.getAppHandler().getInputParams().flush();
			}
		}
	}


	private void guiInitialize(){

		if (_mw != null){
			_mw.getInformationLabelField().setText(LabelManager.get("COMPUTING_SIGNATURE"));
			_mw.SignButton.setEnabled(false);
			_mw.jTree.setEnabled(false);

			_mw.getGlobalProgressBar().setIndeterminate(false);
			_mw.getGlobalProgressBar().setVisible(true);
			_mw.getGlobalProgressBar().setStringPainted(true);
		}
	}

	private void guiFinalize(boolean hideWindow) 
	throws Exception{
		if (_mw != null){
			if (showSignatureOk && hideWindow==true){ 
				JOptionPane.showMessageDialog(_mw.getMainFrame(), LabelManager.get("SIGN_PROCESS_OK"), "", JOptionPane.INFORMATION_MESSAGE);
				_mw.getAppHandler().getOutputParams().signOk();
			}
			_mw.getGlobalProgressBar().setVisible(false);
			_mw.jTree.setEnabled(true);
			_mw.SignButton.setEnabled(true);

			if (hideWindow)
				_mw.mainFrame.setVisible(false);

		}
		this._ini_percent= 0;
		this._end_percent= 100;
		
		if (showSignatureOk && hideWindow==false){
			_mw.getAppHandler().getOutputParams().signOk();
		}
	} 

	public void setMainWindow(MainWindow mw)
	{
		_mw= mw;
	}

	public void setShowSignatureOk(boolean b) {
		showSignatureOk = b;

	}
}
