package es.uji.security.ui.applet;

import org.apache.log4j.Logger;

import es.uji.security.util.i18n.LabelManager;

public class SignatureHandler
{
    private static Logger log = Logger.getLogger(SignatureHandler.class);

    static AppHandler aph = null;
    static int signatureCount = 0;
    static int start = 0;
    static boolean mustStop = false;

    public SignatureHandler(AppHandler aph)
    {

        this.aph = aph;

        try
        {
            mustStop = false;
            signatureCount = aph.getInput().getInputCount();
        }
        catch (Exception e)
        {
            aph.getMainWindow().getInformationLabelField().setText(
                    LabelManager.get("ERROR_CANNOT_GET_INPUT_DATA"));
        }
    }

    public void stop()
    {
        start = 0;

        if (aph != null)
        {
            aph.getInput().flush();
            aph.getOutputParams().flush();
        }

        mustStop = true;

        log.info("Stop has been pressed");
    }

    public void doSign()
    {
        int aux_start, aux_end;

        log.info("Performing signature " + start + "/" + signatureCount);

        SignatureThread sth = new SignatureThread("thread-sig", start);
        sth.setMainWindow(aph.getMainWindow());

        if (signatureCount != 1)
        {
            aux_start = (start) * (100 / signatureCount);
            aux_end = (start + 1) * (100 / signatureCount);
            start = start + 1;
        }
        else
        {
            aux_start = 0;
            aux_end = 100;
            start = 1;
        }

        sth.setPercentRange(aux_start, aux_end, start - 1);
        sth.setCallbackMethod(this);

        if (start == signatureCount || signatureCount == 1)
        {
            sth.setHideWindowOnEnd(true);
            sth.setShowSignatureOk(true);
        }

        if (start > signatureCount)
        {
            start = 0;
            aph.getInput().flush();
            aph.getOutputParams().flush();
            return;
        }

        sth.start();
    }

    public void callback(String error)
    {
        if (error != null)
        {
            log.error(error);
        }

        if ((!mustStop) && (start != signatureCount))
        {
            doSign();
        }
        else
        {
            start = 0;
        }
    }
}
