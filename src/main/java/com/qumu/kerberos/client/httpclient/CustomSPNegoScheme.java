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

    public CustomSPNegoScheme(String userPrincipal, ServiceNameType serviceNameType, final boolean stripPort, final boolean useCanonicalHostname) {
        super(stripPort, useCanonicalHostname);
        this.userPrincipal = userPrincipal;
        this.serviceNameType = serviceNameType;
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
			String prefixAndUser = principalParts[0];

			// Default to HTTP service
			String prefix = "HTTP";
			String realmName = principalParts[1];

			Oid gssNameOid = null;
			String nameStr = null;

			if (prefixAndUser.contains("/")) {

				if (LOG.isDebugEnabled()) {
					LOG.debug("Principal contains a service definition, extracting it to generate GSSName");
				}

				String[] prefixAndHostOrUserParts = prefixAndUser.split("/");
				prefix = prefixAndHostOrUserParts[0];
				realmName = prefixAndHostOrUserParts[1];
			}

			switch (serviceNameType) {
				case HOST_BASED:
					gssNameOid = GSSName.NT_HOSTBASED_SERVICE;
					nameStr = prefix  + "@" + authServer;
					break;
				case USER_BASED:
					//FIXME: currently not working
					gssNameOid =  GSSName.NT_USER_NAME;
					nameStr = prefix + "@" + realmName;
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

			// This is the default implementation: HTTP prefix and host based
			gssName = manager.createName("HTTP@" + authServer, GSSName.NT_HOSTBASED_SERVICE);
		}

		return gssName;
	}
}
