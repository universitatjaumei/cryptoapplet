package es.uji.security.crypto;

import java.util.ArrayList;
import java.util.List;

public class CRLResponseDetails
{
    private boolean valid;
    private List<String> errors;
    
    public CRLResponseDetails()
    {
        this.valid = false;
        this.errors = new ArrayList<String>();
    }
    
    public CRLResponseDetails(boolean valid, ArrayList<String> errors)
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
}
