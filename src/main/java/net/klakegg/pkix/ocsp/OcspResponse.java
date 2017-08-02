package net.klakegg.pkix.ocsp;

import java.util.Date;

/**
 * @author erlend
 */
public class OcspResponse {

    private OcspStatus status;

    private Date thisUpdate;

    private Date nextUpdate;

    protected OcspResponse(OcspStatus ocspStatus, Date thisUpdate, Date nextUpdate) {
        this(ocspStatus);
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
    }

    protected OcspResponse(OcspStatus status) {
        this.status = status;
    }

    public OcspStatus getStatus() {
        return status;
    }

    public Date getThisUpdate() {
        return thisUpdate;
    }

    public Date getNextUpdate() {
        return nextUpdate;
    }

    @Override
    public String toString() {
        return "OcspResponse{" +
                "status=" + status +
                ", thisUpdate=" + thisUpdate +
                ", nextUpdate=" + nextUpdate +
                '}';
    }
}
