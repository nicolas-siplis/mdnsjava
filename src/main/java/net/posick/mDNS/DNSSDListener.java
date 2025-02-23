package net.posick.mDNS;

import net.posick.DNS.Message;

public interface DNSSDListener
{
    public void serviceDiscovered(Object id, ServiceInstance service);
    
    
    public void serviceRemoved(Object id, ServiceInstance service);
    
    
    public void receiveMessage(Object id, Message m);
    
    
    public void handleException(Object id, Exception e);
}
