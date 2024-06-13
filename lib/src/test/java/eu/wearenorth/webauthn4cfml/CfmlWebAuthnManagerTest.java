package eu.wearenorth.webauthn4cfml;

import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.AuthenticationData;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class CfmlWebAuthnManagerTest {
    private final String challenge = "0123456789abcdef0123456789abcdef";
    private final String rpId = "local.wearenorth.eu";
    private final String origin = "https://local.wearenorth.eu:1443";
    private final String userId = "17";
    private final String userName = "jd";
    private final String userDisplayName = "John Doe";

    private final String registrationJson = "{\"rp\":{\"id\":\"http://localhost:8080\",\"name\":\"startRegistration\"},\"user\":{\"id\":\"MTc=\",\"name\":\"jd\",\"displayName\":\"John Doe\"},\"challenge\":{\"value\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"},\"pubKeyCredParams\":[],\"timeout\":60000,\"excludeCredentials\":[],\"authenticatorSelection\":{\"authenticatorAttachment\":\"cross-platform\",\"requireResidentKey\":true,\"residentKey\":\"required\",\"userVerification\":\"required\"},\"attestation\":\"direct\",\"extensions\":null}";

    @Test
    void configCheck() {
        CfmlWebAuthnManager authnManager = new CfmlWebAuthnManager("http://localhost:8080", "configCheck", "http://localhost:8080");
        assertNotEquals(authnManager.rpId, "destination");
        assertEquals(authnManager.rpId, "http://localhost:8080");
        assertEquals(authnManager.rpName, "configCheck");
    }

    @Test
    void startRegistration() throws JsonProcessingException {
        CfmlWebAuthnManager authnManager = new CfmlWebAuthnManager("http://localhost:8080", "startRegistration", "http://localhost:8080");
        String json = authnManager.startRegistration(userId, userName, userDisplayName, "0123456789abcdef0123456789abcdef");
        assertEquals(registrationJson, json);
    }

    @Test
    void startAuthentication() throws JsonProcessingException {
        CfmlWebAuthnManager authnManager = new CfmlWebAuthnManager("local.wearenorth.eu", "startAuthentication", "local.wearenorth.eu");
        String json = authnManager.startAuthentication("0123456789abcdef0123456789abcdef");
        String expected = "{\"challenge\":{\"value\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"},\"timeout\":60000,\"rpId\":\"local.wearenorth.eu\",\"allowCredentials\":[],\"userVerification\":\"discouraged\",\"extensions\":null}";
        assertEquals(expected, json);
    }

    @Test
    void validateAuthentication() throws IOException {
        CfmlWebAuthnManager authnManager = new CfmlWebAuthnManager(rpId, "startRegistration", origin);
        String json = authnManager.startRegistration(userId, userName, userDisplayName, challenge);
        String expected = "{\"rp\":{\"id\":\"local.wearenorth.eu\",\"name\":\"startRegistration\"},\"user\":{\"id\":\"MTc=\",\"name\":\"jd\",\"displayName\":\"John Doe\"},\"challenge\":{\"value\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"},\"pubKeyCredParams\":[],\"timeout\":60000,\"excludeCredentials\":[],\"authenticatorSelection\":{\"authenticatorAttachment\":\"cross-platform\",\"requireResidentKey\":true,\"residentKey\":\"required\",\"userVerification\":\"required\"},\"attestation\":\"direct\",\"extensions\":null}";
        assertEquals(expected, json);
        String response = "{\"id\":\"mDt2p_DABgGJ1GMVyVAgng\",\"rawId\":\"mDt2p_DABgGJ1GMVyVAgng\",\"type\":\"public-key\",\"authenticatorAttachment\":\"platform\",\"response\":{\"attestationObject\":\"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUs3u2GWCB28lVEX741NQy_LyQxQh0h-tXDP5918c0jXNdAAAAALraVWanqkAfvZZFYZpVEg0AEJg7dqfwwAYBidRjFclQIJ6lAQIDJiABIVgg_Tw_gTa-wnQCeIQCTnaqx1Qq1MPcaV0Z8XRvKy_p9uQiWCCimDE4DxKvrho8WpNZo1ez152hgcW3SV0QTMvYcBMZeA\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTURFeU16UTFOamM0T1dGaVkyUmxaakF4TWpNME5UWTNPRGxoWW1Oa1pXWSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWwud2VhcmVub3J0aC5ldToxNDQzIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ\"}}";
        CfmlCredential savedRecord = authnManager.validateRegistration(challenge, response);

        String authResponse = "{\"id\":\"mDt2p_DABgGJ1GMVyVAgng\",\"rawId\":\"mDt2p_DABgGJ1GMVyVAgng\",\"type\":\"public-key\",\"authenticatorAttachment\":\"platform\",\"response\":{\"authenticatorData\":\"s3u2GWCB28lVEX741NQy_LyQxQh0h-tXDP5918c0jXMdAAAAAA\",\"clientDataJSON\":\"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTURFeU16UTFOamM0T1dGaVkyUmxaakF4TWpNME5UWTNPRGxoWW1Oa1pXWSIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWwud2VhcmVub3J0aC5ldToxNDQzIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ\",\"signature\":\"MEUCIQD_5SLrIjZ8Oj1cXDS5VoHZebEsePqMxNAlDi6k1lAerAIgEkQhGB6nl3aB_2GhseWjcd3QmneCCmdffcHRJOaK6ns\",\"userHandle\":\"MTc\"}}";
        AuthenticationData authenticationData = authnManager.parseAuthentication(authResponse);
        System.out.println(authenticationData);
        String credentialId = authnManager.extractCredentialId(authResponse);
        assertEquals("mDt2p_DABgGJ1GMVyVAgng==", credentialId);
        authnManager.validateAuthentication(savedRecord, challenge, authResponse);
    }

}
