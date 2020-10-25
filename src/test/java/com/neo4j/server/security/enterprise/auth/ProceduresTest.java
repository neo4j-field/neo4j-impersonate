package com.neo4j.server.security.enterprise.auth;

import com.neo4j.harness.EnterpriseNeo4jBuilders;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.neo4j.configuration.GraphDatabaseSettings;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.QueryExecutionException;
import org.neo4j.graphdb.Transaction;
import org.neo4j.harness.Neo4j;
import org.neo4j.internal.helpers.collection.Iterators;
import org.neo4j.plugins.impersonate.ImpersonateSettings;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class ProceduresTest {

    private static Neo4j neo4j;
    private static GraphDatabaseService db;


    @BeforeAll
    public static void startNeo4j() {
        neo4j = EnterpriseNeo4jBuilders.newInProcessBuilder()
                .withConfig(GraphDatabaseSettings.auth_enabled, true)
                .withConfig(ImpersonateSettings.prune_close_transactions, Duration.ofMillis(10))
                .withProcedure(Procedures.class)
                .withDisabledServer()
                .build();
        GraphDatabaseService system = neo4j.databaseManagementService().database(GraphDatabaseSettings.SYSTEM_DATABASE_NAME);

        try (Transaction tx= system.beginTx()) {
            tx.execute("create role restricted as copy of reader");
            tx.execute("deny read {salary} ON GRAPHS * to  restricted");
            tx.execute("create user joe set password 'joe'");
            tx.execute("grant role restricted to joe");
            tx.commit();
        }

        db = neo4j.defaultDatabaseService();
        db.executeTransactionally("create (p:Person{name:'John', salary:1000})");
    }

    @AfterAll
    static void stopNeo4j() {
        neo4j.close();
    }

    @Test
    void testImpersonate() {
        db.executeTransactionally("call impersonate('joe', 'match (p:Person{name:$name}) return p ', {name:$name})", Collections.singletonMap("name", "John"),
                result -> {
                    Map<String, Object> map = (Map<String, Object>) Iterators.single(result).get("map");
                    Node person = (Node) map.get("p");
                    assertThat(person.getPropertyKeys()).doesNotContain("salary");
                    return null;
                });
    }

    @Test
    void testImpersonateWithoutParameters() {
        db.executeTransactionally("call impersonate('joe', 'match (p:Person) return p ')", Collections.emptyMap(),
                result -> {
                    Map<String, Object> map = (Map<String, Object>) Iterators.single(result).get("map");
                    Node person = (Node) map.get("p");
                    assertThat(person.getPropertyKeys()).doesNotContain("salary");
                    return null;
                });
    }

    @Test
    void invalidUser() {
        assertThatExceptionOfType(QueryExecutionException.class).isThrownBy(() -> {
            db.executeTransactionally("call impersonate('unknown', 'match (p:Person) return p ')", Collections.emptyMap(), Iterators::single);
        }).havingRootCause().withMessage("invalid user: unknown");
    }

}
