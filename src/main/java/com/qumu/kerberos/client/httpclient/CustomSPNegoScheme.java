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

	private String userPrincipal;
    private ServiceNameType serviceNameType;
    private String servicePrincipal;

    public CustomSPNegoScheme(String userPrincipal, String servicePrincipal, ServiceNameType serviceNameType, final boolean stripPort, final boolean useCanonicalHostname) {
        super(stripPort, useCanonicalHostname);
        this.userPrincipal = userPrincipal;
        this.serviceNameType = serviceNameType;
        this.servicePrincipal = servicePrincipal;
    }

    public CustomSPNegoScheme(String userPrincipal, ServiceNameType serviceNameType, final boolean stripPort, final boolean useCanonicalHostname) {
    	this(userPrincipal, null, serviceNameType, stripPort, useCanonicalHostname);
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
			String servNameSource = serviceNameType != null ? serviceNameType.name() : "null";
			LOG.debug("Generating GSS Name, authServer is: " + authServer + ", principal: " + userPrincipal +
					  ", serviceNameSource: " + servNameSource);
		}

		if (userPrincipal != null || serviceNameType != null) {

			// A user principal is provided along with an strategy to generate the serviceName
			if (LOG.isDebugEnabled()) {
				LOG.debug("Principal is: " + userPrincipal + ", serviceNameType is: " + serviceNameType);
			}

			// HTTP/user.domain.com@DOMAIN.COM or username@DOMAIN.COM
			String[] principalParts = userPrincipal.split("@");

			// We keep the first part
			String prefixAndUserName = principalParts[0];

			// Default to HTTP service
			String prefix = "HTTP";

			Oid gssNameOid = null;
			String nameStr = null;

			if (prefixAndUserName.contains("/")) {

				if (LOG.isDebugEnabled()) {
					LOG.debug("Principal contains a service definition, extracting it to generate GSSName");
				}

				String[] prefixAndHostOrUserParts = prefixAndUserName.split("/");
				prefix = prefixAndHostOrUserParts[0];
			}

			switch (serviceNameType) {
				case HOST_BASED:
					gssNameOid = GSSName.NT_HOSTBASED_SERVICE;
					nameStr = prefix  + "@" + authServer;
					break;
				case USER_BASED:
					// NT_USER_NAME is the same as KRB5_PRINCIPAL_NAME oid
					// Oid KRB5_PRINCIPAL_NAME_OID = new Oid("1.2.840.113554.1.2.2.1");
					gssNameOid =  GSSName.NT_USER_NAME;
					nameStr = servicePrincipal;
					break;
			}

			if (LOG.isDebugEnabled()) {
				LOG.debug("Generated GSSName: " + nameStr);
			}

			// NT_USER_NAME is the same as KRB5_PRINCIPAL_NAME oid
			gssName = manager.createName(nameStr, gssNameOid);

		} else {

			if (LOG.isDebugEnabled()) {
				LOG.debug("Generated GSSName using default (HTTP) prefix and host based OID HTTP@" + authServer);
			}

			// This is the default implementation: HTTP prefix and host based
			gssName = manager.createName("HTTP@" + authServer, GSSName.NT_HOSTBASED_SERVICE);
		}

		return gssName;
	}
}
