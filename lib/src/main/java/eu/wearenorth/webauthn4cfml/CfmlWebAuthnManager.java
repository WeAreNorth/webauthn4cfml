package eu.wearenorth.webauthn4cfml;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.server.ServerProperty;

import static com.webauthn4j.data.AuthenticatorAttachment.CROSS_PLATFORM;

public class CfmlWebAuthnManager {

    public long timeout = 60000;
    public String rpId;
    public String origin;
    public String rpName;
    public Boolean userVerificationRequired = true;
    public Boolean userPresenceRequired = true;
    public WebAuthnManager manager;
    public Set<String> transports = new HashSet<String>();

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Instantiate the CfmlWebAuthnManager
     *
     * @param rpId   A valid domain string identifying the Relying Party: <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#rp-id">...</a>
     * @param rpName <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictionary-pkcredentialentity">...</a>
     * @param origin The fully qualified URL where the authentication is used
     */
    public CfmlWebAuthnManager(String rpId, String rpName, String origin) {
        this.rpId = rpId;
        this.rpName = rpName;
        this.origin = origin;
        this.manager = WebAuthnManager.createNonStrictWebAuthnManager();
    }

    public String startRegistration(String id, String name, String displayName, String challenge)
            throws JsonProcessingException {
        return mapper.writeValueAsString(startRegistration(id.getBytes(), name, displayName, challenge.getBytes()));
    }

    public PublicKeyCredentialCreationOptions startRegistration(byte[] id, String name, String displayName,
                                                                byte[] challenge) {
        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity(rpId, rpName);
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(id, name, displayName);
        List<PublicKeyCredentialDescriptor> excludeCredentials = new ArrayList<PublicKeyCredentialDescriptor>();
        List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<PublicKeyCredentialParameters>();
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria = new AuthenticatorSelectionCriteria(CROSS_PLATFORM, true, ResidentKeyRequirement.REQUIRED, UserVerificationRequirement.REQUIRED);
        return new PublicKeyCredentialCreationOptions(rp, user, new DefaultChallenge(challenge), pubKeyCredParams, timeout, excludeCredentials, authenticatorSelectionCriteria, AttestationConveyancePreference.DIRECT, null);
    }

    public CfmlCredential validateRegistration(String challenge, String registrationResponse) throws IOException {
        CredentialRecord record = validateRegistration(challenge.getBytes(), registrationResponse);
        return new CfmlCredential(record);
    }

    public CredentialRecord validateRegistration(byte[] challenge, String registrationResponse)
            throws IOException {

        Map<String, Object> l1 = mapper.readValue(registrationResponse,
                new TypeReference<HashMap<String, Object>>() {
                });
        Map<String, String> response = (Map<String, String>) l1.get("response");
        RegistrationRequest registrationRequest = new RegistrationRequest(
                Base64.getUrlDecoder().decode(response.get("attestationObject")),
                Base64.getUrlDecoder().decode(response.get("clientDataJSON")),
                null, transports);
        RegistrationData registrationData = manager.parse(registrationRequest);

        ServerProperty serverProperty = new ServerProperty(new Origin(origin), this.rpId,
                new DefaultChallenge(challenge), null);
        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, null, userVerificationRequired, userPresenceRequired);

        manager.validate(registrationData, registrationParameters);
        return new CredentialRecordImpl(
                registrationData.getAttestationObject(),
                registrationData.getCollectedClientData(),
                registrationData.getClientExtensions(),
                registrationData.getTransports()
        );
    }

    public String startAuthentication(String challenge) throws JsonProcessingException {
        return mapper.writeValueAsString(startAuthentication(challenge.getBytes()));
    }

    public PublicKeyCredentialRequestOptions startAuthentication(byte[] challenge) {
        List<PublicKeyCredentialDescriptor> allowCredentials = new ArrayList<PublicKeyCredentialDescriptor>();
        UserVerificationRequirement userVerification = UserVerificationRequirement.DISCOURAGED;
        return new PublicKeyCredentialRequestOptions(new DefaultChallenge(challenge), timeout, rpId, allowCredentials, userVerification, null);
    }

    /**
     * Extract the credentialId from an authentication request without validating the integrity.
     *
     * @param challengeResponse The JSON authentication request received from the browser.
     * @return The credentialId string.
     * @throws IOException
     */
    public String extractCredentialId(String challengeResponse)
            throws IOException {
        AuthenticationData authenticationData = parseAuthentication(challengeResponse);
        return Base64.getUrlEncoder().encodeToString(authenticationData.getCredentialId());
    }

    public AuthenticationData parseAuthentication(String challengeResponse)
            throws IOException {

        Map<String, Object> l1 = mapper.readValue(challengeResponse,
                new TypeReference<HashMap<String, Object>>() {
                });
        Map<String, String> response = (Map<String, String>) l1.get("response");
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                Base64.getUrlDecoder().decode(l1.get("rawId").toString()),
                Base64.getUrlDecoder().decode(response.get("userHandle")),
                Base64.getUrlDecoder().decode(response.get("authenticatorData")),
                Base64.getUrlDecoder().decode(response.get("clientDataJSON")),
                null,
                Base64.getUrlDecoder().decode(response.get("signature"))
        );
        return manager.parse(authenticationRequest);
    }

    public void validateAuthentication(CfmlCredential record, String challenge, String challengeResponse)
            throws IOException {

        AuthenticationData authenticationData = parseAuthentication(challengeResponse);
        ServerProperty serverProperty = new ServerProperty(new Origin(origin), this.rpId,
                new DefaultChallenge(challenge.getBytes()), null);

        CredentialRecord credential = record.deserializeCredentialrecord();
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty,
                credential,
                null,
                userVerificationRequired,
                userPresenceRequired
        );

        manager.validate(authenticationData, authenticationParameters);
    }

}
