<html><head>
<script>
    function bufferToBase64 (buffer) {
        const byteView = new Uint8Array(buffer);
        let str = "";
        for (const charCode of byteView) {
            str += String.fromCharCode(charCode);
        }
        return btoa(str);
    }
    function bufferToBase64url (buffer) {
        const base64String = bufferToBase64(buffer);
        return base64String.replace(/\+/g, "-").replace(/\//g,"_",).replace(/=/g, "");
    }
    function base64urlToByteArray (base64url) {
        return Uint8Array.from(window.atob(base64url), c => c.charCodeAt(0));
    }
    function serializePublicKeyCredential (credential) {
        const serializeable = {
            ...credential,
            rawId: bufferToBase64url(credential.rawId),
            response: {
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
            }
        };
        const serialized = JSON.stringify(serializeable);
        return serialized;
    }
    function serializeAssertion (assertion) {
        const serializeable = {
            ...assertion,
            rawId: bufferToBase64url(assertion.rawId),
            response: {
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: bufferToBase64url(assertion.response.userHandle)
            }
        };
        const serialized = JSON.stringify(serializeable);
        return serialized;
    }
</script>
<script>
    async function register() {
        const challengeRequest = await fetch("./register-step1.cfm");
        const optionsJson = await challengeRequest.json();
        const publicKeyCredentialCreationOptions = {
            ...optionsJson,
            challenge: base64urlToByteArray(optionsJson.challenge.value),
            user: {
                ...optionsJson.user,
                id: base64urlToByteArray(optionsJson.user.id),
            }
        };
        console.dir(publicKeyCredentialCreationOptions);
        credential = await navigator.credentials.create({publicKey: publicKeyCredentialCreationOptions});

        const serializedCredential = serializePublicKeyCredential(credential);
        console.log(serializedCredential);
        const response = await fetch("./register-step2.cfm", {
            method: "POST",
            body: serializedCredential
        });
        console.log(await response.json());
    }

    async function login() {
        const loginRequest = await fetch("./login-step1.cfm");
        const loginJson = await loginRequest.json();
        console.dir(loginJson);
        const credentialsRequestOptions = {
            ...loginJson,
            challenge: base64urlToByteArray(loginJson.challenge.value)
        };
        console.dir(credentialsRequestOptions);
        const assertion = await navigator.credentials.get({publicKey: credentialsRequestOptions});
        console.log(assertion);
        const serializedAssertion = serializeAssertion(assertion);
        console.log(serializedAssertion);
        const response = await fetch("./login-step2.cfm", {
            method: "POST",
            body: serializedAssertion
        });
    }
</script></head>
<body>
<h2>Passwordless auth demo</h2>
<font style="color: #888888"><cfoutput>#now()#</cfoutput></font>
<hr />
<a onclick="register();">Register</a>
<br />
<a onclick="login();">Login</a>
</body></html>
