<cfset session.loginSecret = createGUID() />
<cfset loginOptions = application.webAuthnManager.startAuthentication(session.loginSecret) />
<cfcontent type="application/json" reset="true" /><cfoutput>#loginOptions#</cfoutput>
