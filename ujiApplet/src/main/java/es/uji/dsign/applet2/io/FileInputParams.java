package es.uji.dsign.applet2.io;

import java.io.File;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import es.uji.dsign.applet2.SignatureApplet;
import es.uji.dsign.util.OS;

public class FileInputParams extends AbstractData implements InputParams
{
	public byte[] getSignData(SignatureApplet base) throws Exception
	{	
		JFileChooser chooser = new JFileChooser();
		int returnVal = chooser.showOpenDialog(base);
	

		if( returnVal == JFileChooser.APPROVE_OPTION ) {
			System.out.println("You chose to open this file: " +
					chooser.getSelectedFile().getAbsolutePath());

			File pkFile= chooser.getSelectedFile().getAbsoluteFile();

			if ( ! pkFile.exists() ){
				JOptionPane.showMessageDialog(base, "No se encontró fichero", "", JOptionPane.ERROR_MESSAGE); 
				return null;
			}
			else{

				if (mustHash)
					return this.getMessageDigest(OS.getBytesFromFile(pkFile));
				
				return OS.getBytesFromFile(pkFile);
			}
		}
		return null;
	}

	public String getSignFormat(SignatureApplet base)
	{
		return null;
	}

	public int getInputCount() throws Exception {
		// TODO Auto-generated method stub
		return 0;
	}

	public byte[] getSignData() throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

	public byte[] getSignData(int item) throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

	public void initialize(SignatureApplet base) {
		// TODO Auto-generated method stub
		
	}

	public void flush() {
		// TODO Auto-generated method stub
		
	}
}