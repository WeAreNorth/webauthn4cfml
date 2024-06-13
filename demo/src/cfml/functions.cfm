<cfscript>
function getJsonBody() {
	var json = ToString(GetHttpRequestData().content);
	if (!isJSON(json)) {
		throw (message = "Invalid JSON string", type = "ArgumentException", errorCode = "400")
	}
	return json;
}
function urlSafeBase64Encode(str) {
	return createObject("java", "java.util.Base64").getUrlEncoder().withoutPadding().encodeToString(str.getBytes("UTF-8"));
}
function urlSafeBase64Decode(str) {
	var bytes = createObject("java", "java.util.Base64").getUrlDecoder().decode(str);
	return createObject("java", "java.lang.String").init(bytes);
}
function urlSafeBase64ToBytes(str) {
	var bytes = createObject("java", "java.util.Base64").getUrlDecoder().decode(str);
	return bytes;
}
</cfscript>