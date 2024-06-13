<cfset session.registrationSecret = createGUID() />
<cfset challenge = application.webAuthnManager.startRegistration("user-17", "JD", "John Doe", session.registrationSecret) />
<cfcontent type="application/json" reset="true" /><cfoutput>#challenge#</cfoutput>
