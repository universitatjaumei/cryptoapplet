package es.uji.security.ui.applet.io;

import java.io.File;
import java.io.IOException;
import java.io.FileOutputStream;

import javax.swing.JFileChooser;

import org.apache.log4j.Logger;

public class FileOutputParams implements OutputParams
{
    private Logger log = Logger.getLogger(FileOutputParams.class);
    
    public void setSignData(byte[] data) throws IOException
    {
        JFileChooser chooser = new JFileChooser();
        FileOutputStream fos = null;

        int returnVal = chooser.showSaveDialog(null);

        if (returnVal == JFileChooser.APPROVE_OPTION)
        {
            File pkFile = chooser.getSelectedFile().getAbsoluteFile();
            fos = new FileOutputStream(pkFile);
            fos.write(data);
            fos.close();
        }
    }

    public void setSignFormat(byte[] signFormat) throws IOException
    {
        log.debug("Called setSignFormat: " + new String(signFormat));
    }

    public void signOk()
    {
        log.debug("Called signOk function");
    }

    public void flush()
    {
    }
}