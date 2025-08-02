-- Secure Event Store Database Initialization
-- Enhanced with security features and access controls

-- Create schemas for event store
CREATE SCHEMA IF NOT EXISTS event_store;
CREATE SCHEMA IF NOT EXISTS saga;

-- Set search path
SET search_path TO event_store, public;

-- Create role for event services with limited permissions
CREATE ROLE event_service_role;

-- Events table (immutable event log) with additional security
CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    event_name VARCHAR(255) NOT NULL,
    aggregate_id UUID,
    aggregate_type VARCHAR(255),
    version INTEGER NOT NULL DEFAULT 1,
    occurred_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    metadata JSONB,
    -- Security fields
    publisher_service VARCHAR(100) NOT NULL,
    publisher_id VARCHAR(255) NOT NULL,
    signature VARCHAR(512), -- HMAC signature for event integrity
    encrypted_fields TEXT[], -- List of fields that are encrypted in payload
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Indexes for queries
    INDEX idx_events_aggregate_id (aggregate_id),
    INDEX idx_events_event_name (event_name),
    INDEX idx_events_occurred_at (occurred_at DESC),
    INDEX idx_events_aggregate_version (aggregate_id, version),
    INDEX idx_events_publisher (publisher_service, publisher_id),
    
    -- Ensure version is sequential per aggregate
    CONSTRAINT unique_aggregate_version UNIQUE (aggregate_id, version),
    -- Validate event names to prevent injection
    CONSTRAINT valid_event_name CHECK (event_name ~ '^[a-zA-Z0-9_.-]+$'),
    -- Validate service names
    CONSTRAINT valid_publisher_service CHECK (publisher_service ~ '^[a-zA-Z0-9_-]+$')
);

-- Enable row-level security
ALTER TABLE events ENABLE ROW LEVEL SECURITY;

-- Policy for reading events - services can only read events they're authorized for
CREATE POLICY events_read_policy ON events
    FOR SELECT
    USING (
        -- Check if current user has permission to read this event type
        EXISTS (
            SELECT 1 FROM event_permissions
            WHERE service_name = current_user
            AND event_pattern ~ event_name
            AND permission_type = 'READ'
        )
    );

-- Policy for inserting events - services can only publish their own events
CREATE POLICY events_insert_policy ON events
    FOR INSERT
    WITH CHECK (
        publisher_service = current_user
        AND EXISTS (
            SELECT 1 FROM event_permissions
            WHERE service_name = current_user
            AND event_pattern ~ NEW.event_name
            AND permission_type = 'PUBLISH'
        )
    );

-- Event permissions table
CREATE TABLE IF NOT EXISTS event_permissions (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    event_pattern VARCHAR(255) NOT NULL, -- Regex pattern for event names
    permission_type VARCHAR(20) NOT NULL CHECK (permission_type IN ('READ', 'PUBLISH')),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by VARCHAR(100) NOT NULL,
    UNIQUE(service_name, event_pattern, permission_type)
);

-- Audit log for all event access
CREATE TABLE IF NOT EXISTS event_access_log (
    id BIGSERIAL PRIMARY KEY,
    accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service_name VARCHAR(100) NOT NULL,
    action VARCHAR(20) NOT NULL CHECK (action IN ('READ', 'PUBLISH', 'SUBSCRIBE')),
    event_id UUID,
    event_name VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT
);

-- Rate limiting table
CREATE TABLE IF NOT EXISTS event_rate_limits (
    service_name VARCHAR(100) PRIMARY KEY,
    max_events_per_minute INTEGER NOT NULL DEFAULT 1000,
    max_events_per_hour INTEGER NOT NULL DEFAULT 50000,
    max_payload_size_kb INTEGER NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);

-- Rate limiting tracking
CREATE TABLE IF NOT EXISTS event_rate_tracking (
    service_name VARCHAR(100) NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    window_type VARCHAR(10) NOT NULL CHECK (window_type IN ('MINUTE', 'HOUR')),
    event_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (service_name, window_start, window_type)
);

-- Snapshots table with encryption support
CREATE TABLE IF NOT EXISTS snapshots (
    id BIGSERIAL PRIMARY KEY,
    aggregate_id UUID NOT NULL,
    aggregate_type VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL,
    state JSONB NOT NULL,
    encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_key_id VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(100) NOT NULL,
    
    -- Indexes
    INDEX idx_snapshots_aggregate_id (aggregate_id),
    INDEX idx_snapshots_aggregate_version (aggregate_id, version DESC),
    
    -- Only one snapshot per aggregate/version
    CONSTRAINT unique_snapshot_version UNIQUE (aggregate_id, version)
);

-- Enable RLS on snapshots
ALTER TABLE snapshots ENABLE ROW LEVEL SECURITY;

-- Event subscriptions with authentication
CREATE TABLE IF NOT EXISTS event_subscriptions (
    id SERIAL PRIMARY KEY,
    subscriber_name VARCHAR(255) NOT NULL UNIQUE,
    service_name VARCHAR(100) NOT NULL,
    event_patterns TEXT[] NOT NULL, -- Array of regex patterns
    last_processed_event_id BIGINT,
    last_processed_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    auth_token_hash VARCHAR(255) NOT NULL, -- Hashed authentication token
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    
    CONSTRAINT valid_subscriber_name CHECK (subscriber_name ~ '^[a-zA-Z0-9_.-]+$')
);

-- Saga state table with security enhancements
CREATE TABLE IF NOT EXISTS saga.saga_state (
    id UUID PRIMARY KEY,
    saga_type VARCHAR(255) NOT NULL,
    state VARCHAR(50) NOT NULL DEFAULT 'STARTED',
    current_step VARCHAR(255),
    completed_steps JSONB NOT NULL DEFAULT '[]'::JSONB,
    failed_step VARCHAR(255),
    error TEXT,
    data JSONB NOT NULL DEFAULT '{}'::JSONB,
    -- Security fields
    initiated_by VARCHAR(100) NOT NULL,
    correlation_id UUID NOT NULL,
    timeout_at TIMESTAMPTZ NOT NULL,
    -- Timestamps
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    
    -- Indexes
    INDEX idx_saga_state_type (saga_type),
    INDEX idx_saga_state_status (state),
    INDEX idx_saga_state_started_at (started_at DESC),
    INDEX idx_saga_timeout (timeout_at) WHERE state NOT IN ('COMPLETED', 'FAILED', 'COMPENSATED'),
    
    -- Constraints
    CONSTRAINT valid_saga_type CHECK (saga_type ~ '^[a-zA-Z0-9_.-]+$'),
    CONSTRAINT valid_saga_state CHECK (state IN ('STARTED', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'COMPENSATED', 'TIMED_OUT'))
);

-- Saga events (audit trail for saga execution)
CREATE TABLE IF NOT EXISTS saga.saga_events (
    id BIGSERIAL PRIMARY KEY,
    saga_id UUID NOT NULL REFERENCES saga.saga_state(id) ON DELETE CASCADE,
    event_type VARCHAR(255) NOT NULL,
    event_data JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_saga_events_saga_id (saga_id),
    INDEX idx_saga_events_occurred_at (occurred_at DESC)
);

-- Dead letter queue with retry policies
CREATE TABLE IF NOT EXISTS event_store.dead_letter_queue (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL,
    event_name VARCHAR(255) NOT NULL,
    handler_name VARCHAR(255) NOT NULL,
    error_message TEXT NOT NULL,
    error_count INTEGER NOT NULL DEFAULT 1,
    payload JSONB NOT NULL,
    first_failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_retry_at TIMESTAMPTZ,
    max_retries INTEGER NOT NULL DEFAULT 3,
    retry_backoff_ms INTEGER NOT NULL DEFAULT 1000,
    
    -- Indexes
    INDEX idx_dlq_event_name (event_name),
    INDEX idx_dlq_handler_name (handler_name),
    INDEX idx_dlq_failed_at (last_failed_at DESC),
    INDEX idx_dlq_next_retry (next_retry_at) WHERE error_count < max_retries
);

-- Secure function to append event with validation and rate limiting
CREATE OR REPLACE FUNCTION event_store.append_event_secure(
    p_event_id UUID,
    p_event_name VARCHAR,
    p_aggregate_id UUID,
    p_aggregate_type VARCHAR,
    p_occurred_at TIMESTAMPTZ,
    p_payload JSONB,
    p_metadata JSONB DEFAULT NULL,
    p_signature VARCHAR DEFAULT NULL,
    p_encrypted_fields TEXT[] DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
    v_version INTEGER;
    v_event_id BIGINT;
    v_rate_limit_ok BOOLEAN;
    v_payload_size INTEGER;
BEGIN
    -- Validate inputs
    IF p_event_name !~ '^[a-zA-Z0-9_.-]+$' THEN
        RAISE EXCEPTION 'Invalid event name format';
    END IF;
    
    IF p_aggregate_type IS NOT NULL AND p_aggregate_type !~ '^[a-zA-Z0-9_.-]+$' THEN
        RAISE EXCEPTION 'Invalid aggregate type format';
    END IF;
    
    -- Check payload size
    v_payload_size := length(p_payload::text) / 1024;
    IF v_payload_size > (
        SELECT max_payload_size_kb 
        FROM event_rate_limits 
        WHERE service_name = current_user
    ) THEN
        RAISE EXCEPTION 'Payload size exceeds limit';
    END IF;
    
    -- Check rate limit
    PERFORM event_store.check_rate_limit(current_user);
    
    -- Get next version for aggregate
    SELECT COALESCE(MAX(version), 0) + 1
    INTO v_version
    FROM event_store.events
    WHERE aggregate_id = p_aggregate_id
    FOR UPDATE;
    
    -- Insert event
    INSERT INTO event_store.events (
        event_id, event_name, aggregate_id, aggregate_type,
        version, occurred_at, payload, metadata,
        publisher_service, publisher_id, signature, encrypted_fields
    ) VALUES (
        p_event_id, p_event_name, p_aggregate_id, p_aggregate_type,
        v_version, p_occurred_at, p_payload, p_metadata,
        current_user, session_user, p_signature, p_encrypted_fields
    ) RETURNING id INTO v_event_id;
    
    -- Log access
    INSERT INTO event_store.event_access_log (
        service_name, action, event_id, event_name, success
    ) VALUES (
        current_user, 'PUBLISH', p_event_id, p_event_name, TRUE
    );
    
    RETURN v_event_id;
EXCEPTION
    WHEN OTHERS THEN
        -- Log failed attempt
        INSERT INTO event_store.event_access_log (
            service_name, action, event_id, event_name, success, error_message
        ) VALUES (
            current_user, 'PUBLISH', p_event_id, p_event_name, FALSE, SQLERRM
        );
        RAISE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Rate limiting check function
CREATE OR REPLACE FUNCTION event_store.check_rate_limit(
    p_service_name VARCHAR
) RETURNS VOID AS $$
DECLARE
    v_minute_count INTEGER;
    v_hour_count INTEGER;
    v_limits RECORD;
BEGIN
    -- Get rate limits for service
    SELECT * INTO v_limits
    FROM event_rate_limits
    WHERE service_name = p_service_name;
    
    IF NOT FOUND OR NOT v_limits.enabled THEN
        RETURN;
    END IF;
    
    -- Check minute rate
    INSERT INTO event_rate_tracking (service_name, window_start, window_type, event_count)
    VALUES (p_service_name, date_trunc('minute', NOW()), 'MINUTE', 1)
    ON CONFLICT (service_name, window_start, window_type)
    DO UPDATE SET event_count = event_rate_tracking.event_count + 1
    RETURNING event_count INTO v_minute_count;
    
    IF v_minute_count > v_limits.max_events_per_minute THEN
        RAISE EXCEPTION 'Rate limit exceeded (minute)';
    END IF;
    
    -- Check hour rate
    INSERT INTO event_rate_tracking (service_name, window_start, window_type, event_count)
    VALUES (p_service_name, date_trunc('hour', NOW()), 'HOUR', 1)
    ON CONFLICT (service_name, window_start, window_type)
    DO UPDATE SET event_count = event_rate_tracking.event_count + 1
    RETURNING event_count INTO v_hour_count;
    
    IF v_hour_count > v_limits.max_events_per_hour THEN
        RAISE EXCEPTION 'Rate limit exceeded (hour)';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Secure function to get events with access control
CREATE OR REPLACE FUNCTION event_store.get_aggregate_events_secure(
    p_aggregate_id UUID,
    p_from_version INTEGER DEFAULT NULL,
    p_to_version INTEGER DEFAULT NULL
) RETURNS TABLE (
    event_id UUID,
    event_name VARCHAR,
    version INTEGER,
    occurred_at TIMESTAMPTZ,
    payload JSONB,
    metadata JSONB
) AS $$
BEGIN
    -- Log access attempt
    INSERT INTO event_store.event_access_log (
        service_name, action, success
    ) VALUES (
        current_user, 'READ', TRUE
    );
    
    RETURN QUERY
    SELECT 
        e.event_id,
        e.event_name,
        e.version,
        e.occurred_at,
        e.payload,
        e.metadata
    FROM event_store.events e
    WHERE e.aggregate_id = p_aggregate_id
        AND (p_from_version IS NULL OR e.version >= p_from_version)
        AND (p_to_version IS NULL OR e.version <= p_to_version)
        -- RLS policy will filter based on permissions
    ORDER BY e.version ASC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to handle saga timeouts
CREATE OR REPLACE FUNCTION saga.check_saga_timeouts() RETURNS VOID AS $$
BEGIN
    UPDATE saga.saga_state
    SET state = 'TIMED_OUT',
        updated_at = NOW()
    WHERE state IN ('STARTED', 'IN_PROGRESS')
        AND timeout_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_event_subscriptions_updated_at
    BEFORE UPDATE ON event_store.event_subscriptions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_saga_state_updated_at
    BEFORE UPDATE ON saga.saga_state
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Clean up old rate limit tracking data
CREATE OR REPLACE FUNCTION event_store.cleanup_rate_tracking() RETURNS VOID AS $$
BEGIN
    DELETE FROM event_rate_tracking
    WHERE window_start < NOW() - INTERVAL '2 hours';
END;
$$ LANGUAGE plpgsql;

-- Create roles and permissions
CREATE ROLE auth_service LOGIN PASSWORD 'CHANGE_ME_auth_service_password';
CREATE ROLE user_service LOGIN PASSWORD 'CHANGE_ME_user_service_password';
CREATE ROLE notification_service LOGIN PASSWORD 'CHANGE_ME_notification_service_password';

-- Grant basic permissions
GRANT USAGE ON SCHEMA event_store TO auth_service, user_service, notification_service;
GRANT USAGE ON SCHEMA saga TO auth_service, user_service, notification_service;

-- Grant sequence permissions
GRANT USAGE ON ALL SEQUENCES IN SCHEMA event_store TO auth_service, user_service, notification_service;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA saga TO auth_service, user_service, notification_service;

-- Grant table permissions (RLS will control actual access)
GRANT SELECT, INSERT ON event_store.events TO auth_service, user_service, notification_service;
GRANT SELECT, INSERT ON event_store.event_access_log TO auth_service, user_service, notification_service;
GRANT SELECT ON event_store.event_permissions TO auth_service, user_service, notification_service;
GRANT SELECT ON event_store.event_rate_limits TO auth_service, user_service, notification_service;
GRANT SELECT, INSERT, UPDATE ON event_store.event_rate_tracking TO auth_service, user_service, notification_service;
GRANT SELECT, INSERT, UPDATE ON event_store.event_subscriptions TO auth_service, user_service, notification_service;

-- Grant function permissions
GRANT EXECUTE ON FUNCTION event_store.append_event_secure TO auth_service, user_service, notification_service;
GRANT EXECUTE ON FUNCTION event_store.get_aggregate_events_secure TO auth_service, user_service, notification_service;
GRANT EXECUTE ON FUNCTION event_store.check_rate_limit TO auth_service, user_service, notification_service;

-- Set up initial permissions
INSERT INTO event_store.event_permissions (service_name, event_pattern, permission_type, granted_by) VALUES
    ('auth_service', '^auth\..*', 'PUBLISH', 'system'),
    ('auth_service', '^user\.profile\.created$', 'READ', 'system'),
    ('user_service', '^user\..*', 'PUBLISH', 'system'),
    ('user_service', '^auth\.user\.registered$', 'READ', 'system'),
    ('notification_service', '^auth\.user\.registered$', 'READ', 'system'),
    ('notification_service', '^notification\..*', 'PUBLISH', 'system');

-- Set up rate limits
INSERT INTO event_store.event_rate_limits (service_name) VALUES
    ('auth_service'),
    ('user_service'),
    ('notification_service');

-- Create scheduled job to clean up old data (requires pg_cron extension)
-- SELECT cron.schedule('cleanup-rate-tracking', '0 * * * *', 'SELECT event_store.cleanup_rate_tracking();');
-- SELECT cron.schedule('check-saga-timeouts', '* * * * *', 'SELECT saga.check_saga_timeouts();');