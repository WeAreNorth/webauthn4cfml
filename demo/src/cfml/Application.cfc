component output="false" {
    this.name="webauthn4cfml";
    this.applicationTimeout = createTimeSpan(0,0,30,0);
    this.sessionManagement = true;
    this.javaSettings = {
        loadPaths = [
            "../../../lib/build/libs/lib.jar",
            "../../lib/webauthn4j-core-0.24.0.RELEASE.jar",
            "../../lib/webauthn4j-util-0.24.0.RELEASE.jar",
            "../../lib/jackson-core-2.17.0.jar",
            "../../lib/jackson-annotations-2.17.0.jar",
            "../../lib/jackson-databind-2.17.0.jar",
            "../../lib/jackson-dataformat-cbor-2.17.0.jar",
            "../../lib/jackson-datatype-jsr310-2.17.0.jar",
            "../../lib/jkerby-asn1-2.0.3.jar",
            "../../lib/slf4j-api-2.0.13.jar",
            "../../lib/annotations-24.1.0.jar"
            ], 
        };

    function onApplicationStart() {
        application.webAuthnManager = createObject("java", "eu.wearenorth.webauthn4cfml.CfmlWebAuthnManager")
            .init("localhost", application.applicationName, "http://localhost:8080");
        application.credentials = {};
    }

    function onSessionStart() {
    }
}