package org.traccar.database;


import org.traccar.Config;
import org.traccar.helper.DateUtil;
import org.traccar.helper.Hashing;
import org.traccar.model.PersistentLogin;
import org.traccar.model.User;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.UUID;


public class PersistentLoginManager {

    private final int maximumPersistentLogins;
    private final int expiryDays;
    private final int staleDays;
    private final DataManager dataManager;
    private String cookieName;

    public PersistentLoginManager(DataManager dataManager, Config config) {
        expiryDays = Math.max(1, config.getInteger("persistent.login.expiry.days", 30));
        staleDays = Math.max(1, config.getInteger("persistent.login.stale.days", 7));
        maximumPersistentLogins = Math.max(1, config.getInteger("persistent.login.max", 10));
        cookieName = config.getString("persistent.login.cookie.name", "tcrm");
        if (cookieName.trim().length() == 0) {
            cookieName = "tcrm";
        }
        this.dataManager = dataManager;
    }

    public int getExpiryDays() {
        return expiryDays;
    }

    public int getStaleDays() {
        return staleDays;
    }

    public String getCookieName() {
        return  cookieName;
    }

    public String getCookieValue(PersistentLogin persistentLogin) {
        return  Long.toString(persistentLogin.getId()) + "|" + persistentLogin.getSidToken();
    }

    public Object[]  parseCookieValue(String cookieValue) {
        String[] cookieTokens = cookieValue.split("\\|", 2);
        if (cookieTokens.length != 2) {
            return null;
        }
        if (cookieTokens[1].length() == 0) {
            return null;
        }
        Object[] cookieValues = null;
        try {
            cookieValues = new Object[2];
            cookieValues[0] = Long.parseLong(cookieTokens[0]);
            cookieValues[1] = cookieTokens[1];
        } catch (Exception exception) {
        }
        return cookieValues;
    }

    public void deletePersistentLogin(PersistentLogin persistentLogin) throws SQLException {
        dataManager.deletePersistentLogin(persistentLogin);
    }

    public void deletePersistentLogin(String cookieValue) throws SQLException {
        Object[] cookieValues = parseCookieValue(cookieValue);
        if (cookieValues == null) {
            return;
        }

        PersistentLogin persistentLogin = dataManager.getPersistentLogin((long) cookieValues[0]);
        if (persistentLogin != null && persistentLogin.getSid().equals(cookieValues[1])) {
            dataManager.deletePersistentLogin(persistentLogin);
        }
    }

    public PersistentLogin getPersistentLogin(long id) throws SQLException {
        return dataManager.getPersistentLogin(id);
    }
    public PersistentLogin createPersistentLogin(User user) throws SQLException {
        // If we have more than the allowed persistent logins, we delete the last stale one.
        int persistentLoginCount = dataManager.getUserPersistentLoginCount(user.getId());
        Date today = new Date();
        if (persistentLoginCount >= maximumPersistentLogins) {
            ArrayList<PersistentLogin> userPersistentLogin =
                    new ArrayList(dataManager.getUserPersistentLogins(user.getId()));
            Collections.sort(userPersistentLogin, new Comparator<PersistentLogin>() {
                @Override
                public int compare(PersistentLogin o1, PersistentLogin o2) {
                    Date o1LastUsedDate = o1.getLastUsed() == null ? o1.getCreated() : o1.getLastUsed();
                    Date o2LastUsedDate = o2.getLastUsed() == null ? o2.getCreated() : o2.getLastUsed();
                    return o1LastUsedDate.compareTo(o2LastUsedDate);
                }
            });

            int loginsToDelete = (persistentLoginCount - maximumPersistentLogins) + 1;
            for (int index = 0; index < userPersistentLogin.size(); index++) {
                if (index < loginsToDelete) {
                    dataManager.deletePersistentLogin(userPersistentLogin.get(index));
                } else {
                    PersistentLogin persistentLogin = userPersistentLogin.get(index);
                    if (persistentLogin.getExpiryDate().after(today)) {
                        break;
                    } else {
                        dataManager.deletePersistentLogin(persistentLogin);
                    }
                }
            }
        }

        PersistentLogin persistentLogin = new PersistentLogin();

        persistentLogin.setUserId(user.getId());
        String token = (UUID.randomUUID().toString().replace("-", "") + Hashing.createRandomString(18)).toLowerCase();
        persistentLogin.setSidToken(token);
        persistentLogin.setSalt(Hashing.createRandomString(8));
        persistentLogin.setSid(Hashing.createHash(token, persistentLogin.getSalt()).getHash());
        persistentLogin.setLastUsed(null);
        persistentLogin.setCreated(today);
        persistentLogin.setExpiryDate(DateUtil.dateAdd(today, Calendar.DATE, expiryDays));

        dataManager.insertPersistentLogin(persistentLogin);

        return  persistentLogin;
    }

    public boolean isCookieValid(PersistentLogin persistentLogin, String cookieValue){
        return Hashing.createHash(cookieValue, persistentLogin.getSalt()).getHash().equals(persistentLogin.getSid());
    }

    public void  deleteStalePersistentLogins() throws SQLException {
        Date today = new Date();
        dataManager.deleteStalePersistentLogins(today, DateUtil.dateAdd(today, Calendar.DATE, -1 * getStaleDays()));
    }

    public void updatePersistentLogin(PersistentLogin persistentLogin) throws SQLException {
        dataManager.updatePersistentLogin(persistentLogin);
    }

}
