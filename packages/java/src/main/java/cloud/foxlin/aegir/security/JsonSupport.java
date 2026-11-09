package cloud.foxlin.aegir.security;

/** JSON is data. Never evaluate a server response through a scripting engine. */
final class JsonSupport {
    private JsonSupport() { }
    static Object parse(String input) {
        if (input == null || input.length() > 1048576) throw IntegrationJson.invalid();
        return IntegrationJson.parse(input);
    }
    static String stringify(Object value) { return IntegrationJson.stringify(value); }
}
