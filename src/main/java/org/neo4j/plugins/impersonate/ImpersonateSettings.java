package org.neo4j.plugins.impersonate;

import org.neo4j.annotations.service.ServiceProvider;
import org.neo4j.configuration.Description;
import org.neo4j.configuration.SettingValueParsers;
import org.neo4j.configuration.SettingsDeclaration;
import org.neo4j.graphdb.config.Setting;

import java.time.Duration;

import static org.neo4j.configuration.SettingImpl.newBuilder;

@ServiceProvider
public class ImpersonateSettings implements SettingsDeclaration {

    @Description("how often to check for closed main trainsaction")
    public static final Setting<Duration> prune_close_transactions = newBuilder("plugins.impersonate.prune_closed_transactions", SettingValueParsers.DURATION, Duration.ofSeconds(1)).build();

}
