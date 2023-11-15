package scheper.mateus.api.enums;

public enum StatusEnum {

    ACTIVE("Active"),
    INACTIVE("Inactive");

    private final String status;

    StatusEnum(String status) {
        this.status = status;
    }

    public String getStatus() {
        return status;
    }
}
