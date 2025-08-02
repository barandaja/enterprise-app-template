import { Page, Locator, expect } from '@playwright/test'

export abstract class BasePage {
  readonly page: Page

  constructor(page: Page) {
    this.page = page
  }

  // Navigation helpers
  async goto(path: string) {
    await this.page.goto(path)
    await this.waitForLoad()
  }

  async waitForLoad() {
    await this.page.waitForLoadState('networkidle')
  }

  async reload() {
    await this.page.reload()
    await this.waitForLoad()
  }

  // Element interaction helpers
  async clickElement(selector: string | Locator) {
    const element = typeof selector === 'string' ? this.page.locator(selector) : selector
    await element.click()
  }

  async fillInput(selector: string | Locator, value: string) {
    const element = typeof selector === 'string' ? this.page.locator(selector) : selector
    await element.fill(value)
  }

  async selectOption(selector: string | Locator, value: string) {
    const element = typeof selector === 'string' ? this.page.locator(selector) : selector
    await element.selectOption(value)
  }

  async uploadFile(selector: string | Locator, filePath: string) {
    const element = typeof selector === 'string' ? this.page.locator(selector) : selector
    await element.setInputFiles(filePath)
  }

  // Assertion helpers
  async expectElementVisible(selector: string | Locator) {
    const element = typeof selector === 'string' ? this.page.locator(selector) : selector
    await expect(element).toBeVisible()
  }

  async expectElementHidden(selector: string | Locator) {
    const element = typeof selector === 'string' ? this.page.locator(selector) : selector
    await expect(element).toBeHidden()
  }

  async expectText(selector: string | Locator, text: string) {
    const element = typeof selector === 'string' ? this.page.locator(selector) : selector
    await expect(element).toContainText(text)
  }

  async expectUrl(url: string) {
    await expect(this.page).toHaveURL(url)
  }

  async expectTitle(title: string) {
    await expect(this.page).toHaveTitle(title)
  }

  // Form helpers
  async submitForm(formSelector: string) {
    await this.page.locator(formSelector).dispatchEvent('submit')
  }

  async fillForm(fields: Record<string, string>) {
    for (const [selector, value] of Object.entries(fields)) {
      await this.fillInput(selector, value)
    }
  }

  // Wait helpers
  async waitForSelector(selector: string, options?: { timeout?: number }) {
    return await this.page.waitForSelector(selector, options)
  }

  async waitForResponse(urlPattern: string | RegExp, options?: { timeout?: number }) {
    return await this.page.waitForResponse(urlPattern, options)
  }

  async waitForRequest(urlPattern: string | RegExp, options?: { timeout?: number }) {
    return await this.page.waitForRequest(urlPattern, options)
  }

  // Storage helpers
  async clearStorage() {
    await this.page.evaluate(() => {
      localStorage.clear()
      sessionStorage.clear()
    })
  }

  async setLocalStorage(key: string, value: string) {
    await this.page.evaluate(
      ({ key, value }) => localStorage.setItem(key, value),
      { key, value }
    )
  }

  async getLocalStorage(key: string): Promise<string | null> {
    return await this.page.evaluate(
      (key) => localStorage.getItem(key),
      key
    )
  }

  // Cookie helpers
  async setCookie(name: string, value: string, options?: any) {
    await this.page.context().addCookies([{
      name,
      value,
      url: this.page.url(),
      ...options
    }])
  }

  async getCookie(name: string) {
    const cookies = await this.page.context().cookies()
    return cookies.find(cookie => cookie.name === name)
  }

  async clearCookies() {
    await this.page.context().clearCookies()
  }

  // Screenshot helpers
  async takeScreenshot(name: string) {
    await this.page.screenshot({ path: `screenshots/${name}.png`, fullPage: true })
  }

  // Security helpers
  async checkCSP() {
    const cspHeader = await this.page.evaluate(() => {
      const metaTags = document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]')
      return metaTags.length > 0 ? metaTags[0].getAttribute('content') : null
    })
    return cspHeader
  }

  async checkSecurityHeaders() {
    const response = await this.page.goto(this.page.url())
    const headers = response?.headers() || {}
    
    return {
      csp: headers['content-security-policy'],
      xFrameOptions: headers['x-frame-options'],
      xContentTypeOptions: headers['x-content-type-options'],
      referrerPolicy: headers['referrer-policy'],
      strictTransportSecurity: headers['strict-transport-security']
    }
  }

  // Accessibility helpers
  async checkAccessibility() {
    // Basic accessibility check
    const violations = await this.page.evaluate(() => {
      // Check for missing alt attributes
      const images = document.querySelectorAll('img:not([alt])')
      const buttons = document.querySelectorAll('button:not([aria-label]):not([title])')
      
      return {
        missingAltTexts: images.length,
        unlabeledButtons: buttons.length
      }
    })
    
    return violations
  }

  // Error helpers
  async expectNoConsoleErrors() {
    const errors: string[] = []
    
    this.page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text())
      }
    })
    
    // Wait a bit to collect any errors
    await this.page.waitForTimeout(1000)
    
    expect(errors).toHaveLength(0)
  }

  // Network helpers
  async mockAPI(pattern: string | RegExp, response: any) {
    await this.page.route(pattern, async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response)
      })
    })
  }

  async interceptRequests(pattern: string | RegExp): Promise<any[]> {
    const requests: any[] = []
    
    await this.page.route(pattern, async route => {
      requests.push({
        url: route.request().url(),
        method: route.request().method(),
        headers: route.request().headers(),
        postData: route.request().postData()
      })
      await route.continue()
    })
    
    return requests
  }
}