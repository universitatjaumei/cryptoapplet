package es.uji.security.ui.applet.io;

import java.io.File;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import es.uji.security.ui.applet.SignatureApplet;
import es.uji.security.util.OS;

public class FileInputParams extends AbstractData implements InputParams
{
    public byte[] getSignData() throws Exception
    {
        JFileChooser chooser = new JFileChooser();
        int returnVal = chooser.showOpenDialog(null);

        byte[] data = new byte[] {};
        
        if (returnVal == JFileChooser.APPROVE_OPTION)
        {
            File selectedFile = chooser.getSelectedFile().getAbsoluteFile();
            
            System.out.println("You chose to open this file: " + selectedFile.getAbsolutePath());

            if (! selectedFile.exists())
            {
                JOptionPane.showMessageDialog(null, "No se encontró fichero", "", JOptionPane.ERROR_MESSAGE);
            }
            else
            {
                if (mustHash)
                {
                    data = getMessageDigest(OS.getBytesFromFile(selectedFile));
                }
                else
                {
                    data = OS.getBytesFromFile(selectedFile);
                }
            }
        }
        
        return data;
    }

    public String getSignFormat(SignatureApplet base)
    {
        return null;
    }

    public int getInputCount() throws Exception
    {
        return 1;
    }

    public byte[] getSignData(int item) throws Exception
    {
        return null;
    }

    public void initialize(SignatureApplet base)
    {
    }

    public void flush()
    {
    }
}