package es.uji.security.crypto.config;

public class Device 
{
	private String name;
	private String library;
	private String slot;
	
	public Device()
	{		
	}
	
	public Device(String name, String library, String slot)
	{
		this.name = name;
		this.library = library;
		this.slot = slot;
	}
	
	public String getName() 
	{
		return name;
	}
	
	public void setName(String name) 
	{
		this.name = name;
	}
	
	public String getLibrary() 
	{
		return library;
	}
	
	public void setLibrary(String library) 
	{
		this.library = library;
	}
	
	public String getSlot() 
	{
		return slot;
	}
	
	public void setSlot(String slot) 
	{
		this.slot = slot;
	}
	
	@Override
	public String toString()
	{
		return ("name = " + name + "\r" + 
				"library = " + library + "\r\nslot = " + 
				slot + "\r\n");
	}
}
