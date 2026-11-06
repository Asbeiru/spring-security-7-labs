package com.zhouzhou.agent.security;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/** 固定账户目录；演示只允许租户内调拨。 */
@Component("accountAccess")
public class AccountAccess {
    private final Map<String, String> accountTenants = Map.of(
            "VAULT-A", "tenant-a", "ACC-A001", "tenant-a", "ACC-A002", "tenant-a",
            "VAULT-B", "tenant-b", "ACC-B001", "tenant-b");
    private final Map<String, String> treasuryAccounts = Map.of("tenant-a", "VAULT-A", "tenant-b", "VAULT-B");

    public boolean owns(Authentication authentication, String account) {
        TrustedIdentity identity = TrustedIdentity.from(authentication);
        return account != null && identity.tenant().equals(this.accountTenants.get(account));
    }

    public boolean canTransfer(Authentication authentication, String target, BigDecimal amount) {
        TrustedIdentity identity = TrustedIdentity.from(authentication);
        String source = this.treasuryAccounts.get(identity.tenant());
        if (source == null || !owns(authentication, source) || !owns(authentication, target)
                || source.equals(target) || amount == null || amount.signum() <= 0) {
            return false;
        }
        try {
            amount.setScale(2, RoundingMode.UNNECESSARY);
            return true;
        }
        catch (ArithmeticException ex) {
            return false;
        }
    }

    public String treasury(TrustedIdentity identity) {
        return this.treasuryAccounts.get(identity.tenant());
    }
}
