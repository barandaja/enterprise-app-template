# Testing Framework Documentation

## Overview

This document describes the comprehensive testing framework set up for the React TypeScript frontend application. The framework includes unit tests, integration tests, end-to-end tests, security tests, accessibility tests, and performance tests.

## Architecture

The testing framework follows the testing pyramid principle:

```
           /\
          /  \
         / E2E \
        /      \
       /        \
      /Integration\
     /            \
    /     Unit      \
   /________________\
```

- **Unit Tests**: Fast, isolated tests for individual components and utilities
- **Integration Tests**: Tests for component interactions and data flow
- **E2E Tests**: End-to-end user journey tests using Playwright

## Technology Stack

### Core Testing Libraries
- **Vitest**: Fast unit test runner built on Vite
- **React Testing Library**: Component testing utilities
- **Playwright**: Cross-browser E2E testing
- **MSW**: API mocking for tests
- **jest-axe**: Accessibility testing

### Coverage and Reporting
- **@vitest/coverage-v8**: Code coverage reporting
- **Playwright HTML Reporter**: E2E test reporting
- **GitHub Actions**: CI/CD integration

## Project Structure

```
frontend/
├── src/
│   ├── test/                    # Test utilities and configuration
│   │   ├── setup.ts            # Global test setup
│   │   ├── security-setup.ts   # Security-specific test setup
│   │   ├── utils.tsx           # Test utilities and custom render
│   │   ├── store-utils.ts      # Zustand store testing utilities
│   │   ├── security-utils.ts   # Security testing utilities
│   │   ├── accessibility-utils.ts # A11y testing utilities
│   │   ├── factories.ts        # Test data factories
│   │   └── mocks/             # MSW mock handlers
│   │       ├── server.ts      # Node.js mock server
│   │       ├── browser.ts     # Browser mock worker
│   │       └── handlers.ts    # API mock handlers
│   ├── components/
│   │   └── *.test.tsx         # Component unit tests
│   ├── stores/
│   │   └── *.test.ts          # Store unit tests
│   ├── security/
│   │   └── *.test.ts          # Security component tests
│   └── ...
├── e2e/                        # End-to-end tests
│   ├── pages/                 # Page Object Models
│   │   ├── BasePage.ts       # Base page with common utilities
│   │   ├── LoginPage.ts      # Login page interactions
│   │   ├── RegisterPage.ts   # Registration page interactions
│   │   └── DashboardPage.ts  # Dashboard page interactions
│   ├── global-setup.ts       # E2E global setup
│   ├── global-teardown.ts    # E2E global teardown
│   └── *.spec.ts            # E2E test specs
├── vitest.config.ts          # Vitest configuration
├── vitest.security.config.ts # Security-focused test config
├── playwright.config.ts      # Playwright configuration
├── lighthouserc.js          # Lighthouse CI configuration
└── .github/workflows/test.yml # CI/CD pipeline
```

## Configuration Files

### Vitest Configuration (`vitest.config.ts`)
- Environment: jsdom
- Coverage provider: v8
- Coverage thresholds: 80% across all metrics
- Test timeout: 10 seconds
- Parallel execution enabled

### Security Testing Configuration (`vitest.security.config.ts`)
- Higher coverage thresholds (90%)
- Sequential test execution for deterministic behavior
- Specialized security test setup

### Playwright Configuration (`playwright.config.ts`)
- Cross-browser testing (Chrome, Firefox, Safari)
- Mobile device testing
- Visual regression testing
- Performance monitoring

## Test Categories

### 1. Unit Tests

**Location**: `src/**/*.test.{ts,tsx}`
**Command**: `npm run test`

Unit tests cover:
- Component rendering and behavior
- Utility functions
- State management (Zustand stores)
- Security utilities
- Input validation
- Error handling

Example:
```typescript
describe('Button Component', () => {
  it('should render with correct props', () => {
    render(<Button variant="primary">Click me</Button>)
    expect(screen.getByRole('button')).toHaveClass('btn-primary')
  })
})
```

### 2. Security Tests

**Location**: `src/security/**/*.test.ts`
**Command**: `npm run test:security`

Security tests cover:
- Crypto operations (Web Crypto API)
- Input sanitization
- CSRF protection
- XSS prevention
- Authentication flows
- Rate limiting
- Access control

Example:
```typescript
describe('KeyManager Security', () => {
  it('should generate cryptographically secure keys', async () => {
    const key = await keyManager.generateEncryptionKey()
    expect(key.extractable).toBe(false)
    expect(key.algorithm.length).toBe(256)
  })
})
```

### 3. Integration Tests

Integration tests use the same framework as unit tests but focus on:
- API integration with MSW mocks
- Store-component interactions
- Form submissions
- Authentication flows
- Error boundaries

### 4. End-to-End Tests

**Location**: `e2e/**/*.spec.ts`
**Command**: `npm run test:e2e`

E2E tests cover:
- Complete user journeys
- Cross-browser compatibility
- Mobile responsiveness
- Performance benchmarks
- Visual regression testing
- Security penetration testing

Example:
```typescript
test('should complete login flow', async ({ page }) => {
  const loginPage = new LoginPage(page)
  await loginPage.goto()
  await loginPage.loginWithValidCredentials()
  await loginPage.expectLoginSuccess()
})
```

### 5. Accessibility Tests

**Integration**: Throughout all test types
**Utilities**: `src/test/accessibility-utils.ts`

A11y tests cover:
- WCAG 2.1 AA compliance
- Keyboard navigation
- Screen reader compatibility
- Focus management
- Color contrast
- ARIA attributes

Example:
```typescript
it('should be accessible', async () => {
  const component = render(<Button>Accessible Button</Button>)
  await a11yUtils.testComponentA11y(component)
})
```

## Test Utilities

### Data Factories (`src/test/factories.ts`)
Generate consistent test data:
```typescript
const user = userFactory.build()
const credentials = authFactory.buildLoginCredentials()
const apiResponse = apiResponseFactory.buildSuccess(data)
```

### Store Testing (`src/test/store-utils.ts`)
Test Zustand stores:
```typescript
await testStoreAction(
  useAuthStore,
  () => store.login(credentials),
  { isAuthenticated: true }
)
```

### Security Testing (`src/test/security-utils.ts`)
Mock crypto operations and test security scenarios:
```typescript
const securityUtils = createSecurityTestUtils()
const mockCrypto = securityUtils.mockCrypto
```

### Custom Render (`src/test/utils.tsx`)
Enhanced render with providers:
```typescript
const { user } = render(<Component />)
await user.click(button)
```

## Mock Service Worker (MSW)

### API Mocking
MSW intercepts API calls and provides consistent responses:

```typescript
// src/test/mocks/handlers.ts
export const authHandlers = [
  http.post('/api/auth/login', async ({ request }) => {
    const body = await request.json()
    return HttpResponse.json({ success: true, data: mockUser })
  })
]
```

### Development Integration
Enable MSW in development:
```typescript
// Add to environment variables
VITE_ENABLE_MSW=true
```

## Coverage and Reporting

### Coverage Thresholds
- **Unit Tests**: 80% (branches, functions, lines, statements)
- **Security Tests**: 90% (higher bar for security-critical code)

### Reports Generated
- HTML coverage report: `coverage/index.html`
- JSON coverage data: `coverage/coverage-final.json`
- Playwright HTML report: `playwright-report/index.html`
- Lighthouse performance reports

## CI/CD Integration

### GitHub Actions Workflow
The testing pipeline includes:

1. **Lint and TypeCheck**: Code quality validation
2. **Unit Tests**: Fast feedback on component logic
3. **Security Tests**: Focused security validation
4. **Coverage**: Ensure adequate test coverage
5. **E2E Tests**: Cross-browser user journey validation
6. **Accessibility Tests**: WCAG compliance verification
7. **Performance Tests**: Lighthouse benchmarks
8. **Visual Regression**: Screenshot comparisons

### Parallel Execution
Tests run in parallel for faster feedback:
- Unit tests: Multiple Node.js versions
- E2E tests: Multiple browsers simultaneously
- Security tests: Dedicated runner for thorough analysis

## Running Tests

### Local Development
```bash
# Unit tests
npm run test                 # Interactive mode
npm run test:run            # Single run
npm run test:watch          # Watch mode
npm run test:coverage       # With coverage

# Security tests
npm run test:security       # Security-focused tests

# E2E tests
npm run test:e2e            # All browsers
npm run test:e2e:ui         # Interactive UI
npm run test:e2e:headed     # Visible browser

# All tests
npm run test:all            # Unit + E2E
```

### CI Environment
Tests automatically run on:
- Push to main/develop branches
- Pull requests
- Scheduled runs (nightly)

## Best Practices

### Test Structure
Follow the Arrange-Act-Assert pattern:
```typescript
it('should do something', async () => {
  // Arrange
  const user = userFactory.build()
  
  // Act
  render(<Component user={user} />)
  
  // Assert
  expect(screen.getByText(user.name)).toBeInTheDocument()
})
```

### Test Data
- Use factories for consistent test data
- Avoid hardcoded values
- Make tests independent and isolated

### Async Testing
```typescript
// Wait for elements
await screen.findByText('Loading complete')

// Wait for actions
await waitFor(() => {
  expect(mockApi).toHaveBeenCalled()
})

// User interactions
await user.click(button)
await user.type(input, 'text')
```

### Security Testing
- Test both positive and negative scenarios
- Validate input sanitization
- Test authentication boundaries
- Verify CSRF protection
- Check for XSS vulnerabilities

### Accessibility Testing
- Test keyboard navigation
- Verify screen reader compatibility
- Check color contrast
- Validate ARIA attributes
- Test focus management

## Debugging Tests

### Debug Unit Tests
```bash
# Debug specific test
npm run test -- --reporter=verbose Button.test.tsx

# Debug with UI
npm run test:ui
```

### Debug E2E Tests
```bash
# Debug mode
npm run test:e2e:headed

# Step through tests
npm run test:e2e:ui

# Screenshots and videos
# Automatically captured on failure
```

### Common Issues
1. **Test timeouts**: Increase timeout or optimize async operations
2. **Flaky tests**: Add proper waits and make tests deterministic
3. **Mock issues**: Ensure mocks are properly reset between tests
4. **Memory leaks**: Clean up subscriptions and timers

## Performance Considerations

### Test Performance
- Unit tests should run in < 1 second each
- E2E tests timeout at 30 seconds
- Parallel execution reduces total time
- Selective test running in development

### CI Optimization
- Cache dependencies (node_modules)
- Use test sharding for large suites
- Run critical tests first
- Fail fast on major issues

## Security Considerations

### Test Data Security
- No real credentials in test files
- Sanitize sensitive data in logs
- Use environment variables for secrets
- Mock external services completely

### Crypto Testing
- Use predictable mocks for deterministic tests
- Test both success and failure scenarios
- Validate key generation and storage
- Test encryption/decryption cycles

## Troubleshooting

### Common Test Failures

1. **"Element not found"**
   ```typescript
   // Use findBy for async elements
   await screen.findByText('Async content')
   
   // Add proper waits
   await waitFor(() => {
     expect(screen.getByText('Content')).toBeInTheDocument()
   })
   ```

2. **"Act warnings"**
   ```typescript
   // Wrap state updates in act
   await act(async () => {
     await store.updateData()
   })
   ```

3. **"Network errors in tests"**
   ```typescript
   // Ensure MSW is properly set up
   beforeAll(() => server.listen())
   afterEach(() => server.resetHandlers())
   afterAll(() => server.close())
   ```

### Getting Help
- Check test output for detailed error messages
- Use `screen.debug()` to see current DOM state
- Review test coverage reports for missing scenarios
- Check CI logs for environment-specific issues

## Future Enhancements

### Planned Improvements
- Visual regression testing with Percy
- Contract testing with Pact
- Load testing with Artillery
- Mutation testing with Stryker
- Advanced security scanning

### Test Metrics
- Track test execution time
- Monitor flaky test rates
- Measure coverage trends
- Performance regression detection

---

For questions or issues with the testing framework, please check the troubleshooting section or create an issue in the repository.