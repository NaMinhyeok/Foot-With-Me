package team4.footwithme.config;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.datasource.LazyConnectionDataSourceProxy;
import team4.footwithme.config.datasource.ReplicationRoutingDataSource;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Profile("prod")
@Configuration
public class DataSourceConfig {

    @ConfigurationProperties(prefix = "spring.datasource.command.hikari")
    @Bean(name = "commandDataSource")
    public DataSource commandDataSource() {
        return DataSourceBuilder.create()
            .type(HikariDataSource.class)
            .build();
    }

    @ConfigurationProperties(prefix = "spring.datasource.query.hikari")
    @Bean(name = "queryDataSource")
    public DataSource queryDataSource() {
        return DataSourceBuilder.create()
            .type(HikariDataSource.class)
            .build();
    }

    @DependsOn({"commandDataSource", "queryDataSource"})
    @Bean
    public DataSource routingDataSource(@Qualifier("commandDataSource") DataSource command,
                                        @Qualifier("queryDataSource") DataSource query) {

        ReplicationRoutingDataSource routingDataSource = new ReplicationRoutingDataSource();

        Map<Object, Object> dataSourceMap = new HashMap<>();

        dataSourceMap.put("command", command);
        dataSourceMap.put("query", query);

        routingDataSource.setTargetDataSources(dataSourceMap);
        routingDataSource.setDefaultTargetDataSource(command);

        return routingDataSource;
    }

    @DependsOn("routingDataSource")
    @Primary
    @Bean
    public DataSource dataSource(DataSource routingDataSource) {
        return new LazyConnectionDataSourceProxy(routingDataSource);
    }

}
