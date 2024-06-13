<cfinclude template="./functions.cfm" />
<cfset jsonBody = getJsonBody() />
<cfset credentialId = application.webAuthnManager.extractCredentialId(jsonBody) />
<cfset credential = application.credentials[credentialId] />
<cfset application.webAuthnManager.validateAuthentication(credential, session.loginSecret, jsonBody) />
<cfcontent type="application/json" reset="true" /><cfoutput>#credential.credentialId#</cfoutput>
