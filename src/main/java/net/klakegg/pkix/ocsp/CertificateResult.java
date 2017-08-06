package net.klakegg.pkix.ocsp;

import java.io.Serializable;
import java.util.Date;

/**
 * @author erlend
 */
public class CertificateResult implements Serializable {

    private static final long serialVersionUID = 1058909599853490115L;

    private CertificateIssuer issuer;

    private CertificateStatus status;

    private Date thisUpdate;

    private Date nextUpdate;

    protected CertificateResult(CertificateStatus certificateStatus, CertificateIssuer issuer,
                                Date thisUpdate, Date nextUpdate) {
        this(certificateStatus);
        this.issuer = issuer;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
    }

    public CertificateIssuer getIssuer() {
        return issuer;
    }

    protected CertificateResult(CertificateStatus certificateStatus) {
        this.status = certificateStatus;
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
