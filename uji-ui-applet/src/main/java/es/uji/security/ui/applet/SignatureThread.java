package es.uji.security.ui.applet;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.net.ssl.SSLHandshakeException;
import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;

import org.apache.log4j.Logger;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.crypto.SignatureResult;
import es.uji.security.crypto.SupportedDataEncoding;
import es.uji.security.crypto.SupportedSignatureFormat;
import es.uji.security.crypto.config.OS;
import es.uji.security.crypto.openxades.OpenXAdESSignatureFactory;
import es.uji.security.keystore.IKeyStore;
import es.uji.security.keystore.X509CertificateHandler;
import es.uji.security.ui.applet.io.InputParams;
import es.uji.security.ui.applet.io.OutputParams;
import es.uji.security.util.Base64;
import es.uji.security.util.HexEncoder;
import es.uji.security.util.i18n.LabelManager;

public class SignatureThread extends Thread
{
    private Logger log = Logger.getLogger(SignatureThread.class);

    private MainWindow _mw = null;
    private int _end_percent = 0;
    private int _ini_percent = 0, _step = 0;
    private boolean hideWindow;
    private boolean showSignatureOk;
    private SignatureHandler signatureHandler;
    private int currentIndex;

    public SignatureThread(String str, int currentIndex)
    {
        super(str + "-" + currentIndex);
        this.currentIndex = currentIndex;
    }

    public void setPercentRange(int ini_percent, int end_percent, int step)
    {
        this._step = step;
        this._ini_percent = ini_percent;
        this._end_percent = end_percent;
    }

    public void setHideWindowOnEnd(boolean hideWindow)
    {
        this.hideWindow = hideWindow;
    }

    public void setCallbackMethod(SignatureHandler signatureHandler)
    {
        this.signatureHandler = signatureHandler;
    }

    public void run()
    {
        guiInitialize();
        JLabel infoLabelField = _mw.getInformationLabelField();
        infoLabelField.setText(LabelManager.get("COMPUTING_SIGNATURE"));

        int inc = (this._end_percent - this._ini_percent) / 10;

        try
        {
            X509CertificateHandler selectedNode = getSelectedCertificate();

            IKeyStore iksh = selectedNode.getKeyStore();

            if (iksh == null)
            {
                showSignatureOk = false;
                guiFinalize(false);
                throw new SignatureAppletException("ERR_GET_KEYSTORE");
            }

            loadCertificateStore(infoLabelField, selectedNode, iksh);

            InputParams inputParams = retrieveInputParams(inc);
            OutputParams outputParams = retrieveOutputParams(inc);

            _mw.getGlobalProgressBar().setValue(_ini_percent + 3 * inc);

            log.debug("Loading signature format: " + _mw.getAppHandler().getSignatureFormat().toString());

            // Creating an instance of the signature formater: CMS, XAdES, etc
            Class<?> sf = Class.forName(_mw.getAppHandler().getSignatureFormat().toString());
            ISignFormatProvider signer = (ISignFormatProvider) sf.newInstance();
            SignatureOptions sigOpt = new SignatureOptions();

            String[] roles = _mw.getAppHandler().getSignerRole();

            if (roles != null && this._step < roles.length)
            {
                sigOpt.setSignerRole(roles[this._step]);
                log.debug("Signer Role: " + sigOpt.getSignerRole());
            }

            if (_mw.getAppHandler().getSignatureFormat().equals(SupportedSignatureFormat.XADES))
            {
                String fname = (_mw.getAppHandler().getXadesFileName() != null) ? _mw
                        .getAppHandler().getXadesFileName() : "UNSET";
                String fmimetype = (_mw.getAppHandler().getXadesFileMimeType() != null) ? _mw
                        .getAppHandler().getXadesFileMimeType() : "application/binary";

                log.debug("File Name: " + fname);
                log.debug("Content Type:" + fmimetype);

                OpenXAdESSignatureFactory xs = (OpenXAdESSignatureFactory) signer;
                xs.setXadesFileName(fname);
                xs.setXadesFileMimeType(fmimetype);
            }

            _mw.getGlobalProgressBar().setValue(_ini_percent + 4 * inc);

            if (_mw.jTree.getLastSelectedPathComponent() != null)
            {
                X509CertificateHandler xcert;
                try
                {
                    xcert = (X509CertificateHandler) ((DefaultMutableTreeNode) _mw.jTree
                            .getLastSelectedPathComponent()).getUserObject();
                }
                catch (NullPointerException e)
                {
                    showSignatureOk = false;
                    guiFinalize(false);
                    throw new SignatureAppletException("ERROR_CERTIFICATE_NOT_SELECTED");

                }

                if (xcert.isDigitalSignatureCertificate() || xcert.isNonRepudiationCertificate() ||
                        (xcert.isEmailProtectionCertificate() &&
                                _mw.getAppHandler().getSignatureFormat().equals(SupportedSignatureFormat.CMS)))
                {
                    checkDniAgainstCertificate(xcert);

                    log.debug("Selected a digital signature certificate");

                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    InputStream inputStream = new ByteArrayInputStream(OS.inputStreamToByteArray(inputParams.getSignData(currentIndex)));

                    SupportedDataEncoding encoding = _mw.getAppHandler().getInputDataEncoding();

                    inputStream = decodeInputData(inc, byteArrayOutputStream, inputStream, encoding);

                    if (_mw.isShowSignatureEnabled() && !_mw.getAppHandler().getIsBigFile())
                    {
                        int sel = JOptionPane.showConfirmDialog(_mw.getMainFrame(), _mw
                                .getShowDataScrollPane(OS.inputStreamToByteArray(inputStream)), LabelManager
                                .get("LABEL_SHOW_DATA_WINDOW"), JOptionPane.OK_CANCEL_OPTION);
                        if (sel != JOptionPane.OK_OPTION)
                        {
                            _mw.getAppHandler().callJavaScriptCallbackFunction(
                                    _mw.getAppHandler().getJsSignCancel(), new String[]{});
                            showSignatureOk = false;
                            guiFinalize(true);
                            return;
                        }
                        inputStream.reset();
                    }

                    _mw.getGlobalProgressBar().setValue(_ini_percent + 6 * inc);

                    IKeyStore keyStore = xcert.getKeyStore();

                    log.debug(Collections.list(keyStore.aliases()));

                    SignatureResult signatureResult = signDocument(signer, sigOpt, xcert, inputStream, keyStore);

                    checkSignatureValidity(infoLabelField, signatureResult);
                    deliverOutputResult(inc, outputParams, signatureResult);
                }

                _mw.getGlobalProgressBar().setValue(_ini_percent + 8 * inc);
            }

            _mw.getGlobalProgressBar().setValue(_ini_percent + 10 * inc);

            guiFinalize(hideWindow);

            signatureHandler.callback(null);
        }
        catch (SSLHandshakeException e)
        {
            processError(infoLabelField, "ERROR_SSL", e);
        }
        catch (ClassCastException e)
        {
            processError(infoLabelField, "ERROR_CERTIFICATE_NOT_SELECTED", e);
        }
        catch (NullPointerException e)
        {
            processError(infoLabelField, "ERROR_COMPUTING_SIGNATURE", e);
        }
        catch (IOException e)
        {
            processError(infoLabelField, "ERROR_INPUT_SOURCE", e);
        }
        catch (Exception e)
        {
            processError(infoLabelField, e.getMessage(), e);
        }
    }

    private SignatureResult signDocument(ISignFormatProvider signer, SignatureOptions sigOpt,
                                         X509CertificateHandler xcert, InputStream inputStream, IKeyStore kAux)
            throws SignatureAppletException
    {
        SignatureResult signatureResult;
        try
        {
            initSignatureOptions(sigOpt, xcert, inputStream, kAux);

            log.debug("Signing data");

            signatureResult = signer.formatSignature(sigOpt);
        }
        catch (Exception e)
        {
            log.error(LabelManager.get("ERROR_COMPUTING_SIGNATURE"), e);
            _mw.getAppHandler().callJavaScriptCallbackFunction(
                    _mw.getAppHandler().getJsSignError(),
                    new String[]{LabelManager.get("ERROR_COMPUTING_SIGNATURE") + ":" + e.getMessage()});
            throw new SignatureAppletException(LabelManager.get("ERROR_COMPUTING_SIGNATURE"));
        }
        return signatureResult;
    }

    private void initSignatureOptions(SignatureOptions sigOpt, X509CertificateHandler xcert, InputStream inputStream,
                                      IKeyStore kAux) throws Exception
    {
        sigOpt.setDataToSign(inputStream);
        sigOpt.setCertificate(xcert.getCertificate());

        PrivateKey privateKey = (PrivateKey) kAux.getKey(xcert.getAlias());

        log.debug("Private key format: " + privateKey.getFormat());
        log.debug("Private key algorithm: " + privateKey.getAlgorithm());

        sigOpt.setPrivateKey(privateKey);

        log.debug("Provider: " + kAux.getProvider().getName());

        sigOpt.setProvider(kAux.getProvider());
        sigOpt.setSwapToFile(_mw.getAppHandler().getIsBigFile());

        if (_mw.getAppHandler().getSignatureFormat().equals(SupportedSignatureFormat.JXADES))
        {
            if (_mw.getAppHandler().getXAdESBaseRef() != null)
            {
                String[] baseRefs = _mw.getAppHandler().getXAdESBaseRef();
                sigOpt.setReferences(Arrays.asList(baseRefs));
            }

            sigOpt.setCoSignEnabled(_mw.getAppHandler().isCosign());
            sigOpt.setEnveloped(_mw.getAppHandler().isEnveloped());
            sigOpt.setDetached(_mw.getAppHandler().isDetached());
        }

        if (_mw.getAppHandler().getSignatureFormat().equals(SupportedSignatureFormat.CMS_HASH))
        {
            sigOpt.setHash(true);
        }
        else if (_mw.getAppHandler().getSignatureFormat().equals(SupportedSignatureFormat.PDF) ||
                _mw.getAppHandler().getSignatureFormat().equals(SupportedSignatureFormat.PADES))
        {
            definePDFSignatureOptions(sigOpt);
        }
    }

    private InputStream decodeInputData(int inc, ByteArrayOutputStream ot, InputStream in, SupportedDataEncoding encoding) throws IOException
    {
        log.debug("Encoding: " + encoding);

        _mw.getGlobalProgressBar().setValue(_ini_percent + 5 * inc);

        if (encoding.equals(SupportedDataEncoding.HEX))
        {
            byte[] inData = OS.inputStreamToByteArray(in);
            log.debug("Data from Hex is " + inData.length + " bytes long");

            HexEncoder h = new HexEncoder();
            h.decode(new String(inData), ot);
            in = new ByteArrayInputStream(ot.toByteArray());
        }
        else if (encoding.equals(SupportedDataEncoding.BASE64))
        {
            byte[] inData = OS.inputStreamToByteArray(in);
            log.debug("Data from Base64 is " + inData.length + " bytes long");

            in = new ByteArrayInputStream(Base64.decode(inData));
        }
        return in;
    }

    private void checkDniAgainstCertificate(X509CertificateHandler xcert) throws SignatureAppletException
    {
        String dniToCheck = _mw.getAppHandler().getDniToCheckAgainsCertificate();

        if (dniToCheck != null)
        {
            String dnCertificate = xcert.getCertificate().getSubjectX500Principal().getName();

            if (!dnCertificate.contains(dniToCheck))
            {
                log.error("Error checking DNI " + dniToCheck + " against certificate DN");
                _mw.getAppHandler().callJavaScriptCallbackFunction(
                        _mw.getAppHandler().getJsSignError(),
                        new String[]{LabelManager.get("ERROR_CHECKING_DNI_AGAINST_CERTIFICATE_DN")});
                throw new SignatureAppletException(LabelManager.get("ERROR_CHECKING_DNI_AGAINST_CERTIFICATE_DN"));
            }
        }
    }

    private void loadCertificateStore(JLabel infoLabelField, X509CertificateHandler selectedNode, IKeyStore iksh)
            throws Exception
    {
        log.debug("Loading certificate store");

        try
        {
            iksh.load(_mw.getPasswordTextField().getText().toCharArray());

            log.debug("Certificate store loaded");
        }
        catch (Exception e)
        {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(os);
            e.printStackTrace(ps);
            String stk = new String(os.toByteArray()).toLowerCase();

            if (stk.indexOf("incorrect") > -1)
            {
                showSignatureOk = false;
                guiFinalize(false);
                throw new SignatureAppletException("ERROR_INCORRECT_PWD");
            }
            else
            {
                infoLabelField.setText("Unexpected error!!!");
            }

            e.printStackTrace();
        }
        System.out.println("Certificate Alias: " + iksh.getAliasFromCertificate(selectedNode.getCertificate()));
    }

    private void processError(JLabel infoLabelField, String keyOrMessage, Exception e)
    {
        e.printStackTrace();
        String message = LabelManager.get(keyOrMessage);
        if (null == message){ // if key is not found the key defaults to be the message
            message = keyOrMessage;
        }
        infoLabelField.setText(message);
        signatureHandler.callback(e.getMessage());

        try
        {
            showSignatureOk = false;
            guiFinalize(false);
        }
        catch (Exception e1)
        {
            infoLabelField.setText(LabelManager.get("ERROR_CANNOT_CLOSE_WINDOW"));
            signatureHandler.callback(LabelManager.get("ERROR_CANNOT_CLOSE_WINDOW"));
        }
    }

    private void deliverOutputResult(int inc, OutputParams outputParams, SignatureResult signatureResult)
            throws SignatureAppletException
    {
        SupportedDataEncoding encoding;
        _mw.getGlobalProgressBar().setValue(_ini_percent + 7 * inc);

        if (signatureResult != null && signatureResult.isValid())
        {
            log.debug("The signature is valid");

            try
            {
                encoding = _mw.getAppHandler().getOutputDataEncoding();
                InputStream res = null;

                log.debug("Encoding for output " + encoding);

                if (encoding.equals(SupportedDataEncoding.HEX))
                {
                    byte[] tmp = OS.inputStreamToByteArray(signatureResult.getSignatureData());
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    HexEncoder h = new HexEncoder();
                    h.encode(tmp, 0, tmp.length, bos);
                    res = new ByteArrayInputStream(bos.toByteArray());
                }
                else if (encoding.equals(SupportedDataEncoding.BASE64))
                {
                    res = new ByteArrayInputStream(Base64.encodeBytesToBytes(
                            OS.inputStreamToByteArray(signatureResult.getSignatureData())));
                }
                else
                {
                    res = signatureResult.getSignatureData();
                }

                outputParams.setSignData(res, currentIndex);
            }
            catch (Exception e)
            {
                log.error("Exception decoding data", e);
                _mw.getAppHandler().callJavaScriptCallbackFunction(
                        _mw.getAppHandler().getJsSignError(),
                        new String[]{LabelManager.get("ERROR_CANNOT_SET_OUTPUT_DATA") + e.getMessage()});
                throw new SignatureAppletException(LabelManager.get("ERROR_CANNOT_SET_OUTPUT_DATA"));
            }
        }
        else
        {
            log.error("The signature is NOT valid");
        }
    }

    private void checkSignatureValidity(JLabel infoLabelField, SignatureResult signatureResult) throws Exception
    {
        if (signatureResult == null || !signatureResult.isValid())
        {
            log.debug("The signature is not valid");

            String errorMessage = LabelManager.get("ERROR_COMPUTING_SIGNATURE");

            for (String msg : signatureResult.getErrors())
            {
                log.debug("Signature validation error: " + msg);
                errorMessage += (" - " + msg);
            }

            log.error(errorMessage);

            infoLabelField.setText(errorMessage);

            showSignatureOk = false;
            guiFinalize(false);
            _mw.getAppHandler().getInputParams().flush();

            throw new SignatureAppletException(errorMessage, false);
        }
    }

    private void definePDFSignatureOptions(SignatureOptions sigOpt)
    {
        log.debug("Define PDF options");

        Map<String, String> result = new HashMap<String, String>();

        for (Entry<String, String[]> entry : _mw._aph.getBindValues().entrySet())
        {
            result.put(entry.getKey(), getValue(entry.getValue()));
            log.debug("Bind key: " + entry.getKey() + ", Bind value: " + getValue(entry.getValue()));
        }

        sigOpt.setBindValues(result);

        if (hasValue(_mw._aph.getReason()))
        {
            sigOpt.setReason(getValue(_mw._aph.getReason()));
            log.debug("Reason: " + getValue(_mw._aph.getReason()));
        }

        if (hasValue(_mw._aph.getLocation()))
        {
            sigOpt.setLocation(getValue(_mw._aph.getLocation()));
            log.debug("Location: " + getValue(_mw._aph.getLocation()));
        }

        if (hasValue(_mw._aph.getContact()))
        {
            sigOpt.setContact(getValue(_mw._aph.getContact()));
            log.debug("Contact: " + getValue(_mw._aph.getContact()));
        }

        if (hasValue(_mw._aph.getTimestamping()))
        {
            sigOpt.setTimestamping(getValue(_mw._aph.getTimestamping()).equals("true"));
            log.debug("Timestamping: " + getValue(_mw._aph.getTimestamping()));
        }

        if (hasValue(_mw._aph.getTsaURL()))
        {
            sigOpt.setTsaURL(getValue(_mw._aph.getTsaURL()));
            log.debug("TsaURL: " + getValue(_mw._aph.getTsaURL()));
        }

        if (hasValue(_mw._aph.getVisibleSignature()))
        {
            sigOpt.setVisibleSignature(getValue(_mw._aph.getVisibleSignature()).equals("true"));
            log.debug("VisibleSignature: " + getValue(_mw._aph.getVisibleSignature()));
        }

        if (hasValue(_mw._aph.getVisibleSignatureType()))
        {
            sigOpt.setVisibleSignatureType(getValue(_mw._aph.getVisibleSignatureType()));
            log.debug("VisibleSignatureType: " + getValue(_mw._aph.getVisibleSignatureType()));
        }

        if (hasValue(_mw._aph.getVisibleAreaX()))
        {
            sigOpt.setVisibleAreaX(new Integer(getValue(_mw._aph.getVisibleAreaX())));
            log.debug("VisibleAreaX: " + getValue(_mw._aph.getVisibleAreaX()));
        }

        if (hasValue(_mw._aph.getVisibleAreaY()))
        {
            sigOpt.setVisibleAreaY(new Integer(getValue(_mw._aph.getVisibleAreaY())));
            log.debug("VisibleAreaY: " + getValue(_mw._aph.getVisibleAreaY()));
        }

        if (hasValue(_mw._aph.getVisibleAreaX2()))
        {
            sigOpt.setVisibleAreaX2(new Integer(getValue(_mw._aph.getVisibleAreaX2())));
            log.debug("VisibleAreaX2: " + getValue(_mw._aph.getVisibleAreaX2()));
        }

        if (hasValue(_mw._aph.getVisibleAreaY2()))
        {
            sigOpt.setVisibleAreaY2(new Integer(getValue(_mw._aph.getVisibleAreaY2())));
            log.debug("VisibleAreaY2: " + getValue(_mw._aph.getVisibleAreaY2()));
        }

        if (hasValue(_mw._aph.getVisibleAreaPage()))
        {
            sigOpt.setVisibleAreaPage(getValue(_mw._aph.getVisibleAreaPage()));
            log.debug("VisibleAreaPage: " + getValue(_mw._aph.getVisibleAreaPage()));
        }

        if (hasValue(_mw._aph.getVisibleAreaTextSize()))
        {
            sigOpt.setVisibleAreaTextSize(new Integer(getValue(_mw._aph.getVisibleAreaTextSize())));
            log.debug("VisibleAreaTextSize: " + getValue(_mw._aph.getVisibleAreaTextSize()));
        }

        if (hasValue(_mw._aph.getVisibleAreaImgFile()))
        {
            sigOpt.setVisibleAreaImgFile(getValue(_mw._aph.getVisibleAreaImgFile()));
            log.debug("VisibleAreaImgFile: " + getValue(_mw._aph.getVisibleAreaImgFile()));
        }

        if (hasValue(_mw._aph.getVisibleAreaRepeatAxis()))
        {
            sigOpt.setVisibleAreaRepeatAxis(getValue(_mw._aph.getVisibleAreaRepeatAxis()));
            log.debug("VisibleAreaRepeatAxis: " + getValue(_mw._aph.getVisibleAreaRepeatAxis()));
        }

        if (hasValue(_mw._aph.getVisibleAreaTextPattern()))
        {
            sigOpt.setVisibleAreaTextPattern(getValue(_mw._aph.getVisibleAreaTextPattern()));
            log.debug("VisibleAreaTextPattern: " + getValue(_mw._aph.getVisibleAreaTextPattern()));
        }

        if (hasValue(_mw._aph.getDocumentReference()))
        {
            sigOpt.setDocumentReference(getValue(_mw._aph.getDocumentReference()));
            log.debug("DocumentReference: " + getValue(_mw._aph.getDocumentReference()));
        }

        if (hasValue(_mw._aph.getDocumentReferenceVerificationUrl()))
        {
            sigOpt.setDocumentReferenceVerificationUrl(getValue(_mw._aph.getDocumentReferenceVerificationUrl()));
            log.debug("DocumentReferenceVerificationUrl: " + getValue(_mw._aph.getDocumentReferenceVerificationUrl()));
        }
    }

    private OutputParams retrieveOutputParams(int inc)
    {
        _mw.getGlobalProgressBar().setValue(_ini_percent + 2 * inc);

        return (OutputParams) _mw.getAppHandler().getOutputParams();
    }

    private InputParams retrieveInputParams(int inc)
    {
        _mw.getGlobalProgressBar().setValue(_ini_percent + inc);

        return (InputParams) _mw.getAppHandler().getInputParams();
    }

    private X509CertificateHandler getSelectedCertificate() throws Exception
    {
        X509CertificateHandler selectedNode;

        log.debug("Getting selected certificate");

        try
        {
            selectedNode = (X509CertificateHandler) ((DefaultMutableTreeNode) _mw.jTree
                    .getLastSelectedPathComponent()).getUserObject();

            log.debug("Selected certificate:" + selectedNode.getCertificate().getSubjectDN());
        }
        catch (NullPointerException e)
        {
            throw new SignatureAppletException("ERROR_CERTIFICATE_NOT_SELECTED");
        }

        if (!selectedNode.isDigitalSignatureCertificate()
                && !selectedNode.isNonRepudiationCertificate())
        {
            showSignatureOk = false;
            guiFinalize(false);
            throw new SignatureAppletException("ERROR_CERTIFICATE_USE");
        }

        log.debug("Validating certificate");

        try
        {
            selectedNode.getCertificate().checkValidity();

            log.debug("The certificate is valid");
        }
        catch (CertificateException cex)
        {
            int selection = JOptionPane.showOptionDialog(_mw.getMainFrame(), LabelManager
                            .get("LABEL_CERTIFICATE_EXPIRED"), LabelManager
                            .get("LABEL_CERTIFICATE_EXPIRED_TITLE"), JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE, null, new String[]{"Yes", "No"}, "No"
            );
            if (selection == JOptionPane.NO_OPTION)
            {
                showSignatureOk = false;
                guiFinalize(false);
                throw new SignatureAppletException("ERROR_CERTIFICATE_EXPIRED");
            }
        }
        return selectedNode;
    }

    private String getValue(String[] values)
    {
        if (values.length == 1 || this._step >= values.length)
        {
            return values[0];
        }
        else
        {
            return values[this._step];
        }
    }

    private boolean hasValue(String[] element)
    {
        return (element != null && element.length > 0);
    }

    private void guiInitialize()
    {
        if (_mw != null)
        {
            _mw.getInformationLabelField().setText(LabelManager.get("COMPUTING_SIGNATURE"));
            _mw.SignButton.setEnabled(false);
            _mw.jTree.setEnabled(false);

            _mw.getGlobalProgressBar().setIndeterminate(false);
            _mw.getGlobalProgressBar().setVisible(true);
            _mw.getGlobalProgressBar().setStringPainted(true);
        }
    }

    private void guiFinalize(boolean hideWindow) throws Exception
    {
        if (_mw != null)
        {
            if (showSignatureOk && hideWindow == true)
            {
                JOptionPane.showMessageDialog(_mw.getMainFrame(), LabelManager
                        .get("SIGN_PROCESS_OK"), "", JOptionPane.INFORMATION_MESSAGE);
                _mw.getAppHandler().getOutputParams().signOk();
            }
            _mw.getGlobalProgressBar().setVisible(false);
            _mw.jTree.setEnabled(true);
            _mw.SignButton.setEnabled(true);

            if (hideWindow)
            {
                _mw.mainFrame.setVisible(false);
            }
            else
            {
                _mw.getShowSignatureCheckBox().setVisible(true);
            }

        }
        this._ini_percent = 0;
        this._end_percent = 100;

        if (showSignatureOk && hideWindow == false)
        {
            _mw.getAppHandler().getOutputParams().signOk();
        }
    }

    public void setMainWindow(MainWindow mw)
    {
        _mw = mw;
    }

    public void setShowSignatureOk(boolean b)
    {
        showSignatureOk = b;
    }
}
