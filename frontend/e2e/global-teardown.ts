import { FullConfig } from '@playwright/test'

async function globalTeardown(config: FullConfig) {
  console.log('Starting global teardown...')
  
  try {
    // Perform any cleanup operations here
    
    // Could include:
    // - Cleaning up test database
    // - Stopping test services
    // - Clearing test files
    
    console.log('Global teardown completed successfully')
  } catch (error) {
    console.error('Global teardown failed:', error)
    // Don't throw here to avoid masking test failures
  }
}

export default globalTeardown