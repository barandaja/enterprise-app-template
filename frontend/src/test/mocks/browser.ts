import { setupWorker } from 'msw/browser'
import { handlers } from './handlers'

// Setup requests interception using the given handlers for browser environment
export const worker = setupWorker(...handlers)

// Start the worker only in development mode
if (import.meta.env.DEV && import.meta.env.VITE_ENABLE_MSW === 'true') {
  worker.start({
    onUnhandledRequest: 'warn',
  }).catch(console.error)
}