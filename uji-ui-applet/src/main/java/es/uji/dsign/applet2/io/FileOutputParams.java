package es.uji.dsign.applet2.io;

import java.io.File;
import java.io.IOException;
import java.io.FileOutputStream;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import org.apache.log4j.Logger;
import es.uji.dsign.applet2.SignatureApplet;
import es.uji.dsign.util.OS;

public class FileOutputParams implements OutputParams
{
    private SignatureApplet sap;

    public void setSignData(SignatureApplet base, byte[] data) throws IOException
    {
        sap = base;

        JFileChooser chooser = new JFileChooser();
        FileOutputStream fos = null;

        int returnVal = chooser.showSaveDialog(base);

        if (returnVal == JFileChooser.APPROVE_OPTION)
        {
            File pkFile = chooser.getSelectedFile().getAbsoluteFile();
            fos = new FileOutputStream(pkFile);
            fos.write(data);
            fos.close();
        }
    }

    public void setSignFormat(SignatureApplet base, byte[] signFormat)
    {
        // TODO Auto-generated method stub
    }

    public void setSignData(byte[] data) throws IOException
    {
        // TODO Auto-generated method stub

    }

    public void setSignFormat(byte[] signFormat) throws IOException
    {
        // TODO Auto-generated method stub

    }

    public void signOk()
    {
        netscape.javascript.JSObject.getWindow(sap).call("onSignOk", new String[] { "" });
    }

    public void flush()
    {
        // TODO Auto-generated method stub

    }
}
