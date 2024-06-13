<cfinclude template="./functions.cfm" />
<cfset credential = application.webAuthnManager.validateRegistration(session.registrationSecret, getJsonBody()) />
<cfset application.credentials[credential.credentialId] = credential />
<cfcontent type="application/json" reset="true" /><cfoutput>#credential.credentialId#</cfoutput>
