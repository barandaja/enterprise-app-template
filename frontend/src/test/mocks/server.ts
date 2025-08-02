import { setupServer } from 'msw/node'
import { handlers } from './handlers'

// Setup requests interception using the given handlers
export const server = setupServer(...handlers)

// Export handler utilities for test customization
export { handlers } from './handlers'
export { http, HttpResponse } from 'msw'