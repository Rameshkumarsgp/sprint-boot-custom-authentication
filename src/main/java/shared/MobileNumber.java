package shared;

public record MobileNumber(String value) {

    public MobileNumber {
        if (value == null || !value.matches("\\d{8,15}")) {
            throw new InvalidMobileNumberException();
        }
    }

    public static MobileNumber of(String raw) {
        return new MobileNumber(MobileNumberNormalizer.normalize(raw));
    }

    @Override
    public String toString() {
        return "*".repeat(value.length() - 4) + value.substring(value.length() - 4);
    }
}
