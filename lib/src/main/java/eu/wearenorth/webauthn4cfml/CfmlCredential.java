package eu.wearenorth.webauthn4cfml;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import org.jetbrains.annotations.NotNull;

import java.util.Base64;

public class CfmlCredential {

    public String credentialId;
    public String attestedCredentialData;
    public String attestationStatement;
    public String authenticatorExtensions;
    public long counter;

    public String getCredentialId() {
        return credentialId;
    }

    public String getAttestedCredentialData() {
        return attestedCredentialData;
    }

    public String getAttestationStatement() {
        return attestationStatement;
    }

    public String getAuthenticatorExtensions() {
        return authenticatorExtensions;
    }

    public long getCounter() {
        return counter;
    }

    public CfmlCredential() {
    }

    public CfmlCredential(String credentialId, String attestedCredentialData, String attestationStatement, String authenticatorExtensions, long counter) {
        this.credentialId = credentialId;
        this.attestedCredentialData = attestedCredentialData;
        this.attestationStatement = attestationStatement;
        this.authenticatorExtensions = authenticatorExtensions;
        this.counter = counter;
    }

    public CfmlCredential(String credentialId, String attestedCredentialData, String attestationStatement, String authenticatorExtensions, int counter) {
        this.credentialId = credentialId;
        this.attestedCredentialData = attestedCredentialData;
        this.attestationStatement = attestationStatement;
        this.authenticatorExtensions = authenticatorExtensions;
        this.counter = (long) counter;
    }

    private ObjectConverter objectConverter = new ObjectConverter();
    private AttestedCredentialDataConverter attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);

    public CfmlCredential(@NotNull CredentialRecord record) throws JsonProcessingException {
        byte[] id = record.getAttestedCredentialData().getCredentialId();
        this.credentialId = Base64.getUrlEncoder().encodeToString(id);

        byte[] credential = attestedCredentialDataConverter.convert(record.getAttestedCredentialData());
        this.attestedCredentialData = Base64.getUrlEncoder().encodeToString(credential);

        AttestationStatementEnvelope envelope = new AttestationStatementEnvelope(record.getAttestationStatement());
        byte[] serializedEnvelope = objectConverter.getCborConverter().writeValueAsBytes(envelope);
        this.attestationStatement = Base64.getUrlEncoder().encodeToString(serializedEnvelope);

        byte[] serializedAuthenticatorExtensions = objectConverter.getCborConverter().writeValueAsBytes(record.getAuthenticatorExtensions());
        this.authenticatorExtensions = Base64.getUrlEncoder().encodeToString(serializedAuthenticatorExtensions);

        this.counter = record.getCounter();
    }


    public CredentialRecord deserializeCredentialrecord() throws JsonProcessingException {
        byte[] credentialData = Base64.getUrlDecoder().decode(attestedCredentialData);
        AttestedCredentialData credential = attestedCredentialDataConverter.convert(credentialData);

        byte[] attesttaionData = Base64.getUrlDecoder().decode(attestationStatement);
        AttestationStatementEnvelope deserializedEnvelope = objectConverter.getCborConverter().readValue(attesttaionData, AttestationStatementEnvelope.class);
        AttestationStatement attestationStatement = deserializedEnvelope.getAttestationStatement();

        byte[] authenticatorExtensionsData = Base64.getUrlDecoder().decode(authenticatorExtensions);
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions =
                objectConverter.getCborConverter().readValue(authenticatorExtensionsData, AuthenticationExtensionsAuthenticatorOutputs.class);

        return new CredentialRecordImpl(
                attestationStatement,
                null,
                null,
                null,
                counter,
                credential,
                authenticatorExtensions,
                null,
                null,
                null
        );
    }
}

