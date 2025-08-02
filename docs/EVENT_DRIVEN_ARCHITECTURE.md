# Event-Driven Architecture Guide

This guide explains the event-driven architecture implementation for cross-service communication and data consistency.

## Overview

Our microservices architecture uses domain events to:
- Maintain data consistency across services
- Enable loose coupling between services
- Provide audit trails
- Support event sourcing
- Implement saga patterns for distributed transactions

## Architecture Components

### 1. Event Bus
The event bus facilitates asynchronous communication between services.

**Supported Implementations:**
- **Redis** (default for development) - Uses Pub/Sub
- **Kafka** (recommended for production) - Provides durability and scaling
- **RabbitMQ** (alternative) - Good for complex routing
- **In-Memory** (testing only) - For unit tests

### 2. Domain Events
Events represent significant occurrences in the system.

**Event Categories:**
- **Auth Events**: User registration, login, logout, role changes
- **User Events**: Profile updates, preferences, verification
- **System Events**: Data exports, deletions, compliance

### 3. Event Handlers
Services subscribe to events they're interested in.

```python
class UserProfileCreatedHandler(EventHandler):
    async def handle(self, event: UserProfileCreated):
        # Handle the event
        pass
```

### 4. Sagas
Orchestrate complex workflows across multiple services.

**Implemented Sagas:**
- User Registration Saga
- User Deletion Saga (GDPR)
- Password Reset Saga

## Implementation

### Setting Up Event Infrastructure

1. **Start Event Infrastructure**
```bash
# For development (Redis)
docker-compose up redis

# For production (Kafka)
docker-compose -f docker-compose.events.yml up kafka zookeeper

# With UI tools
docker-compose -f docker-compose.events.yml --profile tools up
```

2. **Configure Services**
```python
# In your service startup
from shared.events.config import create_event_bus, create_event_store

# Create event bus
event_bus = await create_event_bus()

# Create event publisher
event_publisher = AuthEventPublisher(event_bus)

# Register handlers
await event_bus.subscribe(UserProfileCreated, UserProfileCreatedHandler())
```

### Publishing Events

```python
# In auth service after user registration
await event_publisher.publish_user_registered(
    user=user,
    roles=["user"]
)
```

### Handling Events

```python
class UserProfileCreatedHandler(EventHandler):
    @property
    def event_type(self):
        return UserProfileCreated
    
    async def handle(self, event: UserProfileCreated):
        # Update auth service state
        user = await get_user(event.user_id)
        user.profile_created = True
        await save_user(user)
```

### Implementing Sagas

```python
# Start a saga
registration_saga = UserRegistrationSaga(event_bus=event_bus)
await registration_saga.handle(user_registered_event)

# Saga handles the workflow:
# 1. Creates user profile
# 2. Sets default preferences
# 3. Sends welcome email
# 4. Updates analytics
```

## Event Flow Examples

### User Registration Flow
```
1. User registers via auth-service
   → Publishes: UserRegistered

2. User service receives UserRegistered
   → Creates profile
   → Publishes: UserProfileCreated

3. Auth service receives UserProfileCreated
   → Updates user status

4. Notification service receives UserRegistered
   → Sends welcome email
   → Publishes: WelcomeEmailSent

5. Analytics service receives UserRegistered
   → Tracks new user
```

### GDPR Data Export Flow
```
1. User requests data export
   → Publishes: UserDataExportRequested

2. All services receive UserDataExportRequested
   → Collect their data
   → Send to export service

3. Export service aggregates data
   → Creates download link
   → Publishes: UserDataExportCompleted

4. Notification service receives UserDataExportCompleted
   → Sends email with download link
```

## Configuration

### Environment Variables
```bash
# Event Bus Type (redis, kafka, rabbitmq)
EVENT_BUS_TYPE=redis

# Redis Configuration
REDIS_EVENT_URL=redis://localhost:6379
REDIS_CHANNEL_PREFIX=events

# Kafka Configuration
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_TOPIC_PREFIX=events
KAFKA_CONSUMER_GROUP=event-handlers

# Event Store
ENABLE_EVENT_STORE=true
EVENT_STORE_TTL_DAYS=90

# Saga Configuration
ENABLE_SAGAS=true
SAGA_TIMEOUT_SECONDS=3600
```

### Docker Compose
```yaml
# Add to your docker-compose.override.yml
services:
  auth-service:
    environment:
      - EVENT_BUS_TYPE=redis
      - REDIS_EVENT_URL=redis://redis:6379
      
  user-service:
    environment:
      - EVENT_BUS_TYPE=redis
      - REDIS_EVENT_URL=redis://redis:6379
```

## Best Practices

### 1. Event Design
- Keep events immutable
- Include all necessary data
- Version your events
- Use past tense names (UserRegistered, not RegisterUser)

### 2. Idempotency
- Handlers should be idempotent
- Check if action already performed
- Use event IDs to detect duplicates

### 3. Error Handling
- Implement retry logic
- Use dead letter queues
- Log failures for investigation
- Implement compensating transactions

### 4. Performance
- Keep handlers fast
- Use async/await properly
- Batch process when possible
- Monitor queue depths

### 5. Testing
```python
# Use in-memory bus for tests
from shared.events.implementations.in_memory_event_bus import InMemoryEventBus

async def test_user_registration():
    event_bus = InMemoryEventBus()
    await event_bus.start()
    
    # Register handler
    handler = MockHandler()
    await event_bus.subscribe(UserRegistered, handler)
    
    # Publish event
    event = UserRegistered(user_id=user_id, email=email, username=username)
    await event_bus.publish(event)
    
    # Wait for processing
    await event_bus.wait_for_events()
    
    # Assert handler called
    assert handler.called
```

## Monitoring

### Metrics to Track
- Event publishing rate
- Event processing rate
- Handler execution time
- Queue depth
- Error rates

### Kafka UI
Access at http://localhost:8090 when running with tools profile:
```bash
docker-compose -f docker-compose.events.yml --profile tools up
```

### Dead Letter Queue
Failed events are stored for investigation:
```sql
SELECT * FROM event_store.dead_letter_queue
WHERE event_name = 'user.registered'
ORDER BY last_failed_at DESC;
```

## Troubleshooting

### Common Issues

1. **Events not being received**
   - Check event bus is running
   - Verify handler registration
   - Check network connectivity
   - Review handler errors

2. **Duplicate events**
   - Implement idempotency
   - Check for multiple handler registrations
   - Verify event IDs are unique

3. **Saga failures**
   - Check saga state in database
   - Review compensation logic
   - Verify timeout settings
   - Check event ordering

4. **Performance issues**
   - Monitor queue depths
   - Scale consumers
   - Batch process events
   - Add more partitions (Kafka)

## Migration Strategy

### Moving from Synchronous to Event-Driven

1. **Phase 1**: Add event publishing alongside existing API calls
2. **Phase 2**: Add event handlers but keep API calls
3. **Phase 3**: Remove API calls, rely on events
4. **Phase 4**: Optimize event flow and handlers

### Adding New Events

1. Define event in shared/events/
2. Add publisher in service
3. Add handlers in consuming services
4. Test with in-memory bus
5. Deploy with feature flag
6. Monitor and optimize

## Security Considerations

1. **Event Encryption**: Sensitive data in events should be encrypted
2. **Access Control**: Limit which services can publish/subscribe
3. **Audit Trail**: All events are logged for compliance
4. **Data Privacy**: Follow GDPR guidelines for event data

## Future Enhancements

1. **Event Sourcing**: Store all state changes as events
2. **CQRS**: Separate read and write models
3. **Schema Registry**: For event schema evolution
4. **CDC**: Change Data Capture for legacy integration
5. **Event Streaming**: Real-time event processing