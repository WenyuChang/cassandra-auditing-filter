package com.cisco.wenyu;

import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.filter.Filter;
import ch.qos.logback.core.spi.FilterReply;

/**
 * Provides the ability to audit specific users accessing Cassandra.
 *
 *
 * The decision to audit messages is based off
 * 
 *  - the whitelist, and
 *  - the blacklist, and
 *  - the message section of the log line which is after the `SLF4JAuditWriter.java:X - ` part.
 *
 * The message section of the log line is split into separate components by `|` boundaries.
 *
 * The logic then between the white|black lists and these components follows
 *
 *  - if a component matches a line in the whitelist then write to audit.log
 *  - if a component matches a line in the blacklist then don't write to audit.log
 *  - otherwise write to audit.log according to the standard DSE auditing configuration.
 *
 *
 * The whitelist is loaded from $CASSANDRA_HOME/conf/audit-whitelist
 * The blacklist is loaded from $CASSANDRA_HOME/conf/audit-blacklist
 *
 *  $CASSANDRA_HOME in an DSE installation is the same as $DSE_HOME/resources/cassandra/conf
 *
 * Further information is found in https://thelastpickle.atlassian.net/browse/CIS-35
 */
public class AuditFilter  extends Filter<ILoggingEvent> {
	private static final Logger LOG = LoggerFactory.getLogger(AuditFilter.class);
	private static final String WHITE_LIST_FILE_NAME = "audit-whitelist";
	private static final String BLACK_LIST_FILE_NAME = "audit-blacklist";

    private List<String> whitelist;
    private List<String> blacklist;

    public AuditFilter() {
    	whitelist = Collections.emptyList();
    	blacklist = Collections.emptyList();
    	
        List<String> wl = Collections.emptyList();
        try {
            Path wlPath = Paths.get(getClass().getClassLoader().getResource(WHITE_LIST_FILE_NAME).toURI());
            if (Files.exists(wlPath)) {
                wl = Files.readAllLines(wlPath, Charset.defaultCharset());
                for (String part : wl) {
                	if(!part.startsWith("#") && part.trim().length()>0) {
                		whitelist.add(part);
                	}
                }
            }
        } catch (Exception ex) {
            LOG.error("Failed to read " + WHITE_LIST_FILE_NAME, ex);
        }
        
        List<String> bl = Collections.emptyList();
        try {
            Path blPath = Paths.get(getClass().getClassLoader().getResource(BLACK_LIST_FILE_NAME).toURI());
            if (Files.exists(blPath)) {
                bl = Files.readAllLines(blPath, Charset.defaultCharset());
                for (String part : bl) {
                	if(!part.startsWith("#") && part.trim().length()>0) {
                		blacklist.add(part);
                	}
                }
            }
        } catch (Exception ex) {
            LOG.error("failed to read " + BLACK_LIST_FILE_NAME, ex);
        }
       
    }

    @Override
    public FilterReply decide(ILoggingEvent event) {
        String[] msgParts = event.getFormattedMessage().split(Pattern.quote("|"));
        int accept = 0;

        for (String part : msgParts) {
            if (whitelist.contains(part)) {
            	accept = 1;
            }
        }
        for (String part : msgParts) {
            if (blacklist.contains(part)) {
            	accept = -1;
            }
        }
        
        if(accept == -1) {
        	return FilterReply.DENY;
        } else if(accept == 1) {
        	return FilterReply.ACCEPT;
        } else {
        	return FilterReply.NEUTRAL;
        }
    }
}
