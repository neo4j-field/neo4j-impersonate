package com.neo4j.server.security.enterprise.auth;  // since we use a package-scope class from Neo4j, we can't change package name

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.neo4j.kernel.enterprise.api.security.EnterpriseLoginContext;
import com.neo4j.kernel.enterprise.api.security.EnterpriseSecurityContext;
import org.neo4j.common.DependencyResolver;
import org.neo4j.dbms.api.DatabaseManagementService;
import org.neo4j.graphdb.Transaction;
import org.neo4j.internal.helpers.collection.Iterators;
import org.neo4j.internal.kernel.api.security.AuthSubject;
import org.neo4j.internal.kernel.api.security.AuthenticationResult;
import org.neo4j.kernel.api.KernelTransaction;
import org.neo4j.kernel.impl.coreapi.InternalTransaction;
import org.neo4j.kernel.internal.GraphDatabaseAPI;
import org.neo4j.logging.Log;
import org.neo4j.plugins.impersonate.TransactionClosingExtensionFactory;
import org.neo4j.procedure.Context;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.Procedure;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.neo4j.configuration.GraphDatabaseSettings.SYSTEM_DATABASE_NAME;

public class Procedures {

    private static Cache<String, Set<String>> userRolesCache = Caffeine.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .maximumSize(100)
            .build();

    private static Cache<String, String> defaultDatabaseCache = Caffeine.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .initialCapacity(1)
            .maximumSize(1)
            .build();

    @Context
    public DependencyResolver resolver;

    @Context
    public GraphDatabaseAPI database;

    @Context
    public Transaction transaction;

    @Context
    public Log log;

    @Procedure( name = "impersonate" )
    public Stream<MapResult> impersonate(@Name( "username" ) String username, @Name("cypher") String cypher,
                                         @Name(value = "params",defaultValue = "{}") Map<String,Object> params)
    {
        DatabaseManagementService dbms = resolver.resolveDependency( DatabaseManagementService.class );
        GraphDatabaseAPI system = (GraphDatabaseAPI) dbms.database(SYSTEM_DATABASE_NAME);

        Set<String> roleNames;
        String defaultDatabaseName;

        // Need to manually resolve roles here since we can't get the securityManager that exists in the authManager
        try (Transaction tx = system.beginTx()) {
            roleNames = userRolesCache.get(username, s -> {

                Map<String, Object> user = Iterators.singleOrNull(tx.execute("show users where user=$user", Collections.singletonMap("user", username)));
                if (user == null) {
                    throw new IllegalArgumentException("invalid user: " + username);
                }

                boolean suspended = (boolean) user.get("suspended");
                if (suspended) {
                    throw new IllegalStateException("cannot impersonate a suspended account : " + username);
                }
                List<String> roles = (List<String>) user.get("roles");
                log.info("caching user roles for " + username + " = " + roles);
                return Set.copyOf(roles);
            });
            defaultDatabaseName = defaultDatabaseCache.get("default",
                    s -> (String) Iterators.single(tx.execute("show databases where default")).get("name")
            );
            tx.commit();
        }

        MultiRealmAuthManager authManager = resolver.resolveDependency( MultiRealmAuthManager.class );
        InternalTransaction impersonateTransaction = database.beginTransaction(
                KernelTransaction.Type.EXPLICIT,
                new ImpersonatedLoginContext(authManager, defaultDatabaseName, username, roleNames)
        );
        log.debug("opened transaction for impersonate " + impersonateTransaction);

        // from 4.2 onwards we can use transaction.
        TransactionClosingExtensionFactory.TransactionClosing transactionClosing = resolver.resolveDependency(TransactionClosingExtensionFactory.TransactionClosing.class);
        transactionClosing.takeCareOf((InternalTransaction) transaction, impersonateTransaction);

        return impersonateTransaction.execute(cypher, params).stream().map(MapResult::new);
    }

    private static class ImpersonatedLoginContext implements EnterpriseLoginContext
    {
        private final MultiRealmAuthManager authManager;
        private final String username;
        private final String defaultDatabase;
        private final Set<String> roles;
        public ImpersonatedLoginContext(MultiRealmAuthManager authManager, String defaultDatabase, String username, Set<String> roles )
        {
            this.authManager = authManager;
            this.defaultDatabase = defaultDatabase;
            this.username = username;
            this.roles = roles;
        }
        @Override
        public Set<String> roles()
        {
            return roles;
        }
        @Override
        public EnterpriseSecurityContext authorize(IdLookup idLookup, String dbName )
        {
            // Need to manually do what StandardEnterpriseLoginContext does here, since we can't get the securityManager that exists in the authManager
            StandardAccessModeBuilder accessModeBuilder =
                    new StandardAccessModeBuilder( true, false, roles, idLookup, dbName, defaultDatabase );
            Set<ResourcePrivilege> privileges = authManager.getPermissions( roles );
            boolean isDefault = dbName.equals( defaultDatabase );
            for ( ResourcePrivilege privilege : privileges )
            {
                if ( privilege.appliesTo( dbName ) || isDefault && privilege.appliesToDefault() )
                {
                    accessModeBuilder.addPrivilege( privilege );
                }
            }
            if ( dbName.equals( SYSTEM_DATABASE_NAME ) )
            {
                accessModeBuilder.withAccess();
            }
            StandardAccessMode mode = accessModeBuilder.build();
            if ( !mode.allowsAccess() )
            {
                throw mode.onViolation(
                        String.format( "Database access is not allowed for user '%s' with roles %s.", username, new TreeSet<>( roles ).toString() ) );
            }
            return new EnterpriseSecurityContext( subject(), mode, mode.roles(), mode.getAdminAccessMode() );
        }
        @Override
        public AuthSubject subject()
        {
            String sudoUsername = username;
            return new AuthSubject()
            {
                @Override
                public void logout()
                {
                }
                @Override
                public AuthenticationResult getAuthenticationResult()
                {
                    return AuthenticationResult.SUCCESS;
                }
                @Override
                public void setPasswordChangeNoLongerRequired()
                {
                }
                @Override
                public boolean hasUsername( String username )
                {
                    return sudoUsername.equals( username );
                }
                @Override
                public String username()
                {
                    return sudoUsername;
                }
            };
        }
    }

    public class MapResult {
        public Map<String, Object> map;

        public MapResult(Map<String, Object> map) {
            this.map = map;
        }
    }

}
