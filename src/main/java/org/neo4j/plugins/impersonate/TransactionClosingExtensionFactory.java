package org.neo4j.plugins.impersonate;

import org.neo4j.annotations.service.ServiceProvider;
import org.neo4j.configuration.Config;
import org.neo4j.kernel.extension.ExtensionFactory;
import org.neo4j.kernel.extension.ExtensionType;
import org.neo4j.kernel.extension.context.ExtensionContext;
import org.neo4j.kernel.impl.coreapi.InternalTransaction;
import org.neo4j.kernel.lifecycle.Lifecycle;
import org.neo4j.kernel.lifecycle.LifecycleAdapter;
import org.neo4j.logging.Log;
import org.neo4j.logging.internal.LogService;
import org.neo4j.scheduler.JobHandle;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@ServiceProvider
public class TransactionClosingExtensionFactory extends ExtensionFactory<TransactionClosingExtensionFactory.Dependencies> {

    public TransactionClosingExtensionFactory() {
        super(ExtensionType.GLOBAL, "transactionClosing");
    }

    @Override
    public Lifecycle newInstance(ExtensionContext context, Dependencies dependencies) {
        return new TransactionClosing(dependencies);
    }

    public interface Dependencies {
        LogService log();
        Config config();
    }

    public static class TransactionClosing extends LifecycleAdapter {

        private final Dependencies dependencies;
        private JobHandle<?> jobHandle;
        private Map<InternalTransaction, InternalTransaction> transactionMap;
        private ScheduledExecutorService scheduledExecutorService;

        public TransactionClosing(Dependencies dependencies) {
            this.dependencies = dependencies;
            transactionMap = new ConcurrentHashMap<>();
        }

        @Override
        public void start() throws Exception {

            Log log = dependencies.log().getInternalLog(TransactionClosingExtensionFactory.class);

            long pruneDurationMillis = dependencies.config().get(ImpersonateSettings.prune_close_transactions).toMillis();

            scheduledExecutorService = Executors.newScheduledThreadPool(1);
            scheduledExecutorService.scheduleAtFixedRate(() -> {
                try {
                    log.info("processing transaction list");
                    transactionMap.keySet().stream().filter(t -> !t.isOpen()).forEach( source -> {
                        InternalTransaction target = transactionMap.remove(source);
                        if (source.terminationReason().isEmpty()) {
                            target.commit();
                        } else {
                            target.rollback();
                        }
                        target.close();
                    });
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }, pruneDurationMillis, pruneDurationMillis, TimeUnit.MILLISECONDS);
        }

        @Override
        public void stop() throws Exception {
            scheduledExecutorService.shutdown();
            scheduledExecutorService.awaitTermination(10, TimeUnit.SECONDS);
        }

        public void takeCareOf(InternalTransaction source, InternalTransaction target) {
            transactionMap.put(source, target);
        }
    }

}
