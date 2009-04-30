package es.uji.security.ui.applet;

import es.uji.dsign.util.i18n.LabelManager;

public class SignatureHandler
{

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

    public static void stop()
    {
        start = 0;

        if (aph != null)
        {
            aph.getInput().flush();
            aph.getOutputParams().flush();
        }

        mustStop = true;
    }

    public static void doSign()
    {
        int aux_start, aux_end;
        try
        {

            SignatureThread sth = new SignatureThread("thread-sig-" + start);
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
            sth.setCallbackMethod(SignatureHandler.class.getMethod("callback"));

            System.out.println("START: " + start + "SIGNATURECOUNT: " + signatureCount);

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
        catch (Exception e)
        {
            start = 0;
            e.printStackTrace();
        }
    }

    /*
     * That function is the one invoked by the signature thread once the signature process has
     * finalized, if there are more signatures on the inputParams stack, the signature thread is
     * instantiated again
     */
    public static void callback()
    {
        System.out.println("\n\n\n\n\nSTART: " + start + " SIGNATURECOUNT: " + signatureCount);
        if ((!mustStop) && (start != signatureCount))
        {
            doSign();
        }
    }
}
