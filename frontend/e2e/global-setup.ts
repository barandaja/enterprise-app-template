import { chromium, FullConfig } from '@playwright/test'

async function globalSetup(config: FullConfig) {
  console.log('Starting global setup...')
  
  // Create a browser instance for setup operations
  const browser = await chromium.launch()
  const context = await browser.newContext()
  const page = await context.newPage()
  
  try {
    // Wait for the application to be ready
    const baseURL = config.webServer?.url || 'http://localhost:5173'
    console.log(`Waiting for application at ${baseURL}`)
    
    await page.goto(baseURL)
    await page.waitForLoadState('networkidle')
    
    // Verify the application is working
    const title = await page.title()
    console.log(`Application is ready. Title: ${title}`)
    
    // Clear any existing data
    await page.evaluate(() => {
      localStorage.clear()
      sessionStorage.clear()
    })
    
    console.log('Global setup completed successfully')
  } catch (error) {
    console.error('Global setup failed:', error)
    throw error
  } finally {
    await context.close()
    await browser.close()
  }
}

export default globalSetup