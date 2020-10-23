package com.neo4j.server.security.enterprise.auth;  // since we use a package-scope class from Neo4j, we can't change package name

import com.neo4j.kernel.enterprise.api.security.EnterpriseLoginContext;
import com.neo4j.kernel.enterprise.api.security.EnterpriseSecurityContext;
import org.neo4j.common.DependencyResolver;
import org.neo4j.dbms.api.DatabaseManagementService;
import org.neo4j.graphalgo.impl.util.PathImpl;
import org.neo4j.graphdb.Direction;
import org.neo4j.graphdb.Label;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Path;
import org.neo4j.graphdb.Relationship;
import org.neo4j.graphdb.RelationshipType;
import org.neo4j.graphdb.Transaction;
import org.neo4j.internal.kernel.api.security.AuthSubject;
import org.neo4j.internal.kernel.api.security.AuthenticationResult;
import org.neo4j.kernel.api.KernelTransaction;
import org.neo4j.kernel.impl.coreapi.InternalTransaction;
import org.neo4j.kernel.internal.GraphDatabaseAPI;
import org.neo4j.logging.Log;
import org.neo4j.procedure.Context;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.Procedure;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.neo4j.configuration.GraphDatabaseSettings.SYSTEM_DATABASE_NAME;

public class Procedures {

    @Context
    public DependencyResolver resolver;

    @Context
    public GraphDatabaseAPI database;

    @Context
    public Transaction transaction;

    @Context
    public Log log;

    @Procedure( name = "impersonate" )
    public Stream<MapResult> sudo(@Name( "username" ) String username, @Name("cypher") String cypher, @Name("params")Map<String,Object> params)
    {
        DatabaseManagementService dbms = resolver.resolveDependency( DatabaseManagementService.class );

        // Starting a transaction on this database will escape security
//        GraphDatabaseAPI database = (GraphDatabaseAPI) dbms.database( "database name goes here" );

        MultiRealmAuthManager authManager = resolver.resolveDependency( MultiRealmAuthManager.class );
        // Need to manually resolve roles here since we can't get the securityManager that exists in the authManager
        GraphDatabaseAPI system = (GraphDatabaseAPI) dbms.database(SYSTEM_DATABASE_NAME);
        Set<String> roleNames = new TreeSet<>();
        String defaultDatabaseName;
        Collection<String> roles = system.executeTransactionally("show roles with users where member = $user", Collections.singletonMap("user", username), result -> result.stream().map( m -> m.get("role").toString()).collect(Collectors.toSet()));

        try ( Transaction tx = system.beginTx() )
        {
            Node userNode = tx.findNode( Label.label( "User" ), "name", username );
            if ( userNode != null )
            {
                boolean suspended = (boolean) userNode.getProperty( "suspended" );
                final Iterable<Relationship> rels = userNode.getRelationships( Direction.OUTGOING, RelationshipType.withName( "HAS_ROLE" ) );
                rels.forEach( rel -> roleNames.add( (String) rel.getEndNode().getProperty( "name" ) ) );
            }
            Node defaultDatabase = tx.findNode( Label.label( "Database" ), "default", true );
            defaultDatabaseName = (String) defaultDatabase.getProperty( "name" );
            tx.commit();
        }

        InternalTransaction internalTransaction = database.beginTransaction(KernelTransaction.Type.EXPLICIT, new SudoLoginContext(authManager, defaultDatabaseName, username, roleNames));

        return internalTransaction.execute(cypher, params).stream().map(MapResult::new).onClose(() -> {
            try {
                internalTransaction.commit();
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
        });
    }


    private static class SudoLoginContext implements EnterpriseLoginContext
    {
        private final MultiRealmAuthManager authManager;
        private final String username;
        private final String defaultDatabase;
        private final Set<String> roles;
        public SudoLoginContext( MultiRealmAuthManager authManager, String defaultDatabase, String username, Set<String> roles )
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
            // rebind node, relationship and path instances to outer transaction
            map.entrySet().forEach(e -> {
                Object val = e.getValue();
                if (val instanceof Node) {
                    Node n = (Node) val;
                    map.put(e.getKey(), transaction.getNodeById(n.getId()));
                } else if (val instanceof Relationship) {
                    Relationship r = (Relationship) val;
                    map.put(e.getKey(), transaction.getNodeById(r.getId()));
                } else if (val instanceof Path) {
                    Path p = (Path) val;
                    Node startNode = transaction.getNodeById(p.startNode().getId());
                    PathImpl.Builder builder = new PathImpl.Builder(startNode);
                    p.relationships().forEach( r -> builder.push(transaction.getRelationshipById(r.getId())));
                    map.put(e.getKey(), builder.build());
                }
            });
        }
    }
}
