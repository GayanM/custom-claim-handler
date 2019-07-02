package org.wso2.carbon.identity.custom.claim.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.claims.impl.DefaultClaimHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.user.api.*;
import org.wso2.carbon.user.core.UserRealm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * ClaimHandler written fixing https://wso2.org/jira/browse/IDENTITY-4250
 * to return user claims in openid connect scenario
 */
public class CustomClaimHandler extends DefaultClaimHandler {

    private static final Log log = LogFactory.getLog(CustomClaimHandler.class);
    private static final String TRAVEL_APP = "Travel_Expense_Management_app";
    private static final String GROUP = "Finance";

    @Override
    protected Map<String, String> handleLocalClaims(String spStandardDialect,
                                                    StepConfig stepConfig,
                                                    AuthenticationContext context) throws FrameworkException {

        Map map = super.handleLocalClaims(spStandardDialect, stepConfig, context);

        //first need find service provider
        ApplicationConfig appConfig = context.getSequenceConfig().getApplicationConfig();
        ServiceProvider serviceProvider = appConfig.getServiceProvider();
        if (TRAVEL_APP.equals(serviceProvider.getApplicationName())) {
            //Need to get authenticated user roles
            AuthenticatedUser authenticatedUser;
            if(stepConfig != null) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
            } else {
                authenticatedUser = context.getSequenceConfig().getAuthenticatedUser();
            }
            Map<ClaimMapping, String> userClaims = authenticatedUser.getUserAttributes();
            ClaimMapping claimMapping = new ClaimMapping();
            Claim claim = new Claim();
            claim.setClaimUri("http://wso2.org/claims/role");
            claimMapping.setLocalClaim(claim);
            String roleValue = userClaims.get(claimMapping);
            if (GROUP.equals(roleValue)) {
                map.put("user-type", "travel-manager");
            } else {
                map.put("user-type", "travel-user");
            }
        }

        //same logic can be repeated for Operational Expense management app as well


        return map;
    }


}
