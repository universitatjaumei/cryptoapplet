package es.uji.security.crypto;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class SignatureResult
{
    private boolean valid;
    private List<String> errors;
    private InputStream signatureData;
    
    public SignatureResult()
    {
        this.valid = false;
        this.errors = new ArrayList<String>();
    }
    
    public SignatureResult(boolean valid, ArrayList<String> errors)
    {
        this.valid = valid;
        this.errors = errors;
    }
    
    public boolean isValid()
    {
        return valid;
    }
    
    public void setValid(boolean valid)
    {
        this.valid = valid;
    }
    
    public List<String> getErrors()
    {
        return errors;
    }
    
    public void setErrors(ArrayList<String> errors)
    {
        this.errors = errors;
    }
    
    public void addError(String error)
    {
        if (this.errors != null)
        {
            this.errors.add(error);
        }
    }

    public InputStream getSignatureData()
    {
        return this.signatureData;
    }

    public void setSignatureData(InputStream signatureData)
    {
        this.signatureData = signatureData;
    }
}
