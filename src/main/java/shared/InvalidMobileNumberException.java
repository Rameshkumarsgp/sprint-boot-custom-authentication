package shared;

public class InvalidMobileNumberException extends RuntimeException {
    public InvalidMobileNumberException() {
        super("Invalid mobile number");
    }
}
