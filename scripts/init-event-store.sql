-- Event Store Database Initialization
-- Creates tables for event sourcing and saga management

-- Create schema for event store
CREATE SCHEMA IF NOT EXISTS event_store;
CREATE SCHEMA IF NOT EXISTS saga;

-- Set search path
SET search_path TO event_store, public;

-- Events table (immutable event log)
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
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Indexes for queries
    INDEX idx_events_aggregate_id (aggregate_id),
    INDEX idx_events_event_name (event_name),
    INDEX idx_events_occurred_at (occurred_at DESC),
    INDEX idx_events_aggregate_version (aggregate_id, version),
    
    -- Ensure version is sequential per aggregate
    CONSTRAINT unique_aggregate_version UNIQUE (aggregate_id, version)
);

-- Snapshots table (for performance optimization)
CREATE TABLE IF NOT EXISTS snapshots (
    id BIGSERIAL PRIMARY KEY,
    aggregate_id UUID NOT NULL,
    aggregate_type VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL,
    state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_snapshots_aggregate_id (aggregate_id),
    INDEX idx_snapshots_aggregate_version (aggregate_id, version DESC),
    
    -- Only one snapshot per aggregate/version
    CONSTRAINT unique_snapshot_version UNIQUE (aggregate_id, version)
);

-- Event subscriptions (for tracking which events have been processed)
CREATE TABLE IF NOT EXISTS event_subscriptions (
    id SERIAL PRIMARY KEY,
    subscriber_name VARCHAR(255) NOT NULL UNIQUE,
    last_processed_event_id BIGINT,
    last_processed_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Saga state table
CREATE TABLE IF NOT EXISTS saga.saga_state (
    id UUID PRIMARY KEY,
    saga_type VARCHAR(255) NOT NULL,
    state VARCHAR(50) NOT NULL DEFAULT 'STARTED',
    current_step VARCHAR(255),
    completed_steps JSONB NOT NULL DEFAULT '[]'::JSONB,
    failed_step VARCHAR(255),
    error TEXT,
    data JSONB NOT NULL DEFAULT '{}'::JSONB,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    
    -- Indexes
    INDEX idx_saga_state_type (saga_type),
    INDEX idx_saga_state_status (state),
    INDEX idx_saga_state_started_at (started_at DESC)
);

-- Saga events (audit trail for saga execution)
CREATE TABLE IF NOT EXISTS saga.saga_events (
    id BIGSERIAL PRIMARY KEY,
    saga_id UUID NOT NULL REFERENCES saga.saga_state(id),
    event_type VARCHAR(255) NOT NULL,
    event_data JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_saga_events_saga_id (saga_id),
    INDEX idx_saga_events_occurred_at (occurred_at DESC)
);

-- Dead letter queue for failed events
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
    
    -- Indexes
    INDEX idx_dlq_event_name (event_name),
    INDEX idx_dlq_handler_name (handler_name),
    INDEX idx_dlq_failed_at (last_failed_at DESC)
);

-- Function to append event with version checking
CREATE OR REPLACE FUNCTION event_store.append_event(
    p_event_id UUID,
    p_event_name VARCHAR,
    p_aggregate_id UUID,
    p_aggregate_type VARCHAR,
    p_occurred_at TIMESTAMPTZ,
    p_payload JSONB,
    p_metadata JSONB DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
    v_version INTEGER;
    v_event_id BIGINT;
BEGIN
    -- Get next version for aggregate
    SELECT COALESCE(MAX(version), 0) + 1
    INTO v_version
    FROM event_store.events
    WHERE aggregate_id = p_aggregate_id;
    
    -- Insert event
    INSERT INTO event_store.events (
        event_id, event_name, aggregate_id, aggregate_type,
        version, occurred_at, payload, metadata
    ) VALUES (
        p_event_id, p_event_name, p_aggregate_id, p_aggregate_type,
        v_version, p_occurred_at, p_payload, p_metadata
    ) RETURNING id INTO v_event_id;
    
    RETURN v_event_id;
END;
$$ LANGUAGE plpgsql;

-- Function to get events for aggregate
CREATE OR REPLACE FUNCTION event_store.get_aggregate_events(
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
    ORDER BY e.version ASC;
END;
$$ LANGUAGE plpgsql;

-- Function to update saga state
CREATE OR REPLACE FUNCTION saga.update_saga_state(
    p_saga_id UUID,
    p_state VARCHAR,
    p_current_step VARCHAR DEFAULT NULL,
    p_completed_step VARCHAR DEFAULT NULL,
    p_failed_step VARCHAR DEFAULT NULL,
    p_error TEXT DEFAULT NULL,
    p_data JSONB DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
    UPDATE saga.saga_state
    SET 
        state = p_state,
        current_step = COALESCE(p_current_step, current_step),
        completed_steps = CASE 
            WHEN p_completed_step IS NOT NULL 
            THEN completed_steps || to_jsonb(p_completed_step)
            ELSE completed_steps
        END,
        failed_step = COALESCE(p_failed_step, failed_step),
        error = COALESCE(p_error, error),
        data = COALESCE(p_data, data),
        updated_at = NOW(),
        completed_at = CASE 
            WHEN p_state IN ('COMPLETED', 'FAILED', 'COMPENSATED') 
            THEN NOW() 
            ELSE completed_at 
        END
    WHERE id = p_saga_id;
    
    -- Log saga event
    INSERT INTO saga.saga_events (saga_id, event_type, event_data)
    VALUES (
        p_saga_id,
        'STATE_CHANGED',
        jsonb_build_object(
            'state', p_state,
            'current_step', p_current_step,
            'completed_step', p_completed_step,
            'failed_step', p_failed_step,
            'error', p_error
        )
    );
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

-- Grant permissions
GRANT ALL ON SCHEMA event_store TO event_user;
GRANT ALL ON SCHEMA saga TO event_user;
GRANT ALL ON ALL TABLES IN SCHEMA event_store TO event_user;
GRANT ALL ON ALL TABLES IN SCHEMA saga TO event_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA event_store TO event_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA saga TO event_user;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA event_store TO event_user;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA saga TO event_user;