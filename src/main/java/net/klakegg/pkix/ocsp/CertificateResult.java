package net.klakegg.pkix.ocsp;

import java.util.Date;

/**
 * @author erlend
 */
public class CertificateResult {

    private CertificateStatus status;

    private Date thisUpdate;

    private Date nextUpdate;

    protected CertificateResult(CertificateStatus certificateStatus, Date thisUpdate, Date nextUpdate) {
        this(certificateStatus);
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
    }

    protected CertificateResult(CertificateStatus status) {
        this.status = status;
    }

    public CertificateStatus getStatus() {
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
        return "CertificateResult{" +
                "status=" + status +
                ", thisUpdate=" + thisUpdate +
                ", nextUpdate=" + nextUpdate +
                '}';
    }
}
