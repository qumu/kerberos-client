package com.qumu.kerberos.client.httpclient;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.KerberosCredentials;
import org.apache.http.impl.auth.SPNegoScheme;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class CustomSPNegoScheme extends SPNegoScheme {
	
	private static final Log LOG = LogFactory.getLog(CustomSPNegoScheme.class);
	
    private String spnPrincipal;
    private ServiceNameSource serviceNameSource; 
    
    public CustomSPNegoScheme(String spnPrincipal, ServiceNameSource serviceNameSource, final boolean stripPort, final boolean useCanonicalHostname) {
        super(stripPort, useCanonicalHostname);
        this.spnPrincipal = spnPrincipal;
        this.serviceNameSource = serviceNameSource;
    }
	
	@Override
	protected byte[] generateGSSToken(
            final byte[] input, final Oid oid, final String authServer,
            final Credentials credentials) throws GSSException {
        byte[] inputBuff = input;
        if (inputBuff == null) {
            inputBuff = new byte[0];
        }
        final GSSManager manager = getManager();
       
        GSSName gssName = generateGSSName(manager, authServer);
        
        final GSSCredential gssCredential;
        if (credentials instanceof KerberosCredentials) {
            gssCredential = ((KerberosCredentials) credentials).getGSSCredential();
        } else {
            gssCredential = null;
        }

        final GSSContext gssContext = manager.createContext(
                gssName.canonicalize(oid), oid, gssCredential, GSSContext.DEFAULT_LIFETIME);
        gssContext.requestMutualAuth(true);
        gssContext.requestCredDeleg(true);
        return gssContext.initSecContext(inputBuff, 0, inputBuff.length);
    }
	
	private GSSName generateGSSName(GSSManager manager, String authServer) throws GSSException {
		
		GSSName gssName;
		
		if (LOG.isDebugEnabled()) {
			LOG.debug("Generating GSS Name, authServer is: " + authServer + ", spnPrincipal: " + spnPrincipal + 
					  ", serviceNameSource: " + serviceNameSource != null ? serviceNameSource.name() : "null");
		}
		
		if (spnPrincipal != null || serviceNameSource != null) {
			
			// A SPN Principal (SPN) is provided along with an strategy to generate the serviceName
			
			// HTTP/user.domain.com@DOMAIN.COM
			String[] spnPrincipalParts = spnPrincipal.split("@");
			
			// We keep HTTP/user.domain.com
			String prefixAndUser = spnPrincipalParts[0];
			
			String[] prefixAndHostOrUserParts = prefixAndUser.split("/");
			String prefix = prefixAndHostOrUserParts[0];
			String hostOrUser = prefixAndHostOrUserParts[1];
			
			Oid gssNameOid = null;
			String nameStr = null;
			
			switch (serviceNameSource) {
				case HOST_BASED:
					gssNameOid = GSSName.NT_HOSTBASED_SERVICE;
					nameStr = prefix  + "@" + authServer;
					break;
				case USER_BASED:
					gssNameOid =  GSSName.NT_USER_NAME;
					nameStr = prefix + "@" + hostOrUser;
					break;
			}
			
			if (LOG.isDebugEnabled()) {
				LOG.debug("Generated GSSName: " + nameStr + ", OID: " + gssNameOid);
			}
			
			gssName = manager.createName(nameStr, gssNameOid);
			
		} else {
			
			if (LOG.isDebugEnabled()) {
				LOG.debug("Generated GSSName using default (HTTP) prefix and host based OID " + "HTTP@" + authServer);
			}
			
			// This is the default: HTTP prefix and host based
			gssName = manager.createName("HTTP@" + authServer, GSSName.NT_HOSTBASED_SERVICE);
		}
		
		return gssName;
	}
	
	
	
}
