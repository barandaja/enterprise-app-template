import { Page, Locator } from '@playwright/test'
import { BasePage } from './BasePage'

export class DashboardPage extends BasePage {
  readonly userMenu: Locator
  readonly logoutButton: Locator
  readonly profileLink: Locator
  readonly settingsLink: Locator
  readonly userAvatar: Locator
  readonly welcomeMessage: Locator
  readonly sidebarToggle: Locator
  readonly navigation: Locator
  readonly mainContent: Locator
  readonly notifications: Locator
  readonly themeToggle: Locator

  constructor(page: Page) {
    super(page)
    this.userMenu = page.getByTestId('user-menu')
    this.logoutButton = page.getByRole('button', { name: /logout|sign out/i })
    this.profileLink = page.getByRole('link', { name: /profile/i })
    this.settingsLink = page.getByRole('link', { name: /settings/i })
    this.userAvatar = page.getByTestId('user-avatar')
    this.welcomeMessage = page.getByTestId('welcome-message')
    this.sidebarToggle = page.getByTestId('sidebar-toggle')
    this.navigation = page.getByRole('navigation')
    this.mainContent = page.getByRole('main')
    this.notifications = page.getByTestId('notifications')
    this.themeToggle = page.getByTestId('theme-toggle')
  }

  async goto() {
    await super.goto('/dashboard')
  }

  async expectUserAuthenticated(userName?: string) {
    await this.expectElementVisible(this.userMenu)
    await this.expectElementVisible(this.welcomeMessage)
    
    if (userName) {
      await this.expectText(this.welcomeMessage, userName)
    }
  }

  async logout() {
    await this.clickElement(this.userMenu)
    await this.clickElement(this.logoutButton)
    
    // Should be redirected to login
    await this.expectUrl(/\/login/)
  }

  async goToProfile() {
    await this.clickElement(this.userMenu)
    await this.clickElement(this.profileLink)
    await this.expectUrl(/\/profile/)
  }

  async goToSettings() {
    await this.clickElement(this.userMenu)
    await this.clickElement(this.settingsLink)
    await this.expectUrl(/\/settings/)
  }

  async toggleSidebar() {
    await this.clickElement(this.sidebarToggle)
    
    // Check if sidebar state changed
    const sidebarClass = await this.navigation.getAttribute('class')
    return sidebarClass?.includes('collapsed') || sidebarClass?.includes('hidden')
  }

  async toggleTheme() {
    const currentTheme = await this.page.evaluate(() => {
      return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
    })
    
    await this.clickElement(this.themeToggle)
    
    // Verify theme changed
    const newTheme = await this.page.evaluate(() => {
      return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
    })
    
    return currentTheme !== newTheme
  }

  async checkNotifications() {
    const notificationCount = await this.notifications.count()
    
    if (notificationCount > 0) {
      await this.clickElement(this.notifications)
      // Check if notification panel opens
      const notificationPanel = this.page.getByTestId('notification-panel')
      await this.expectElementVisible(notificationPanel)
      return true
    }
    
    return false
  }

  // Security testing methods
  async checkSessionTimeout() {
    // Simulate idle time by setting localStorage to expired session
    await this.page.evaluate(() => {
      const expiredTime = Date.now() - (30 * 60 * 1000) // 30 minutes ago
      localStorage.setItem('sessionExpiry', expiredTime.toString())
    })
    
    // Reload page to trigger session check
    await this.reload()
    
    // Should be redirected to login
    const currentUrl = this.page.url()
    return currentUrl.includes('/login')
  }

  async checkCSRFProtection() {
    // Attempt to make request without CSRF token
    const response = await this.page.evaluate(async () => {
      try {
        const response = await fetch('/api/user/profile', {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ name: 'Hacker' })
        })
        return { success: response.ok, status: response.status }
      } catch (error) {
        return { success: false, error: error.message }
      }
    })
    
    // Should be rejected due to missing CSRF token
    return !response.success && (response.status === 403 || response.status === 401)
  }

  async testUnauthorizedAccess() {
    // Clear auth tokens
    await this.clearStorage()
    await this.clearCookies()
    
    // Try to access dashboard
    await this.goto()
    
    // Should be redirected to login
    const currentUrl = this.page.url()
    return currentUrl.includes('/login')
  }

  async checkSecureHeaders() {
    const headers = await this.checkSecurityHeaders()
    
    return {
      hasCSP: !!headers.csp,
      hasXFrameOptions: !!headers.xFrameOptions,
      hasXContentTypeOptions: !!headers.xContentTypeOptions,
      hasReferrerPolicy: !!headers.referrerPolicy,
      hasHSTS: !!headers.strictTransportSecurity
    }
  }

  // Performance testing
  async measurePageLoadTime() {
    const startTime = Date.now()
    
    await this.goto()
    await this.waitForLoad()
    
    const endTime = Date.now()
    return endTime - startTime
  }

  async measureInteractionTime(action: () => Promise<void>) {
    const startTime = Date.now()
    
    await action()
    
    const endTime = Date.now()
    return endTime - startTime
  }

  // Data validation
  async validateUserData() {
    const userData = await this.page.evaluate(() => {
      // Try to access user data from global state
      const userDataElement = document.querySelector('[data-user]')
      if (userDataElement) {
        return JSON.parse(userDataElement.getAttribute('data-user') || '{}')
      }
      return null
    })
    
    return {
      hasUserData: !!userData,
      userData,
      isValid: userData && userData.id && userData.email
    }
  }

  // State persistence testing
  async testStatePersistence() {
    // Perform some actions that should persist
    await this.toggleSidebar()
    const sidebarCollapsed = await this.navigation.getAttribute('class')
    
    await this.toggleTheme()
    const currentTheme = await this.page.evaluate(() => {
      return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
    })
    
    // Reload page
    await this.reload()
    
    // Check if state persisted
    const newSidebarState = await this.navigation.getAttribute('class')
    const newTheme = await this.page.evaluate(() => {
      return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
    })
    
    return {
      sidebarPersisted: sidebarCollapsed === newSidebarState,
      themePersisted: currentTheme === newTheme
    }
  }

  // Error handling testing
  async testErrorBoundary() {
    // Trigger an error by corrupting application state
    await this.page.evaluate(() => {
      // Simulate component error by throwing in React
      const errorButton = document.createElement('button')
      errorButton.textContent = 'Trigger Error'
      errorButton.onclick = () => {
        throw new Error('Test error for error boundary')
      }
      document.body.appendChild(errorButton)
    })
    
    await this.clickElement('button:has-text("Trigger Error")')
    
    // Check if error boundary caught the error
    const errorBoundary = this.page.getByTestId('error-boundary')
    const hasErrorUI = await errorBoundary.count() > 0
    
    return hasErrorUI
  }

  // Accessibility testing
  async checkDashboardAccessibility() {
    const violations = await super.checkAccessibility()
    
    // Check navigation accessibility
    const navHasRole = await this.navigation.getAttribute('role')
    const mainHasRole = await this.mainContent.getAttribute('role')
    
    // Check if interactive elements are keyboard accessible
    const focusableElements = await this.page.$$eval(
      'button, a, input, select, textarea, [tabindex]:not([tabindex="-1"])',
      elements => elements.length
    )
    
    // Check skip links
    const skipLinks = await this.page.locator('a[href^="#"]:has-text("skip")').count()
    
    return {
      ...violations,
      navigationAccessible: navHasRole === 'navigation',
      mainContentAccessible: mainHasRole === 'main',
      focusableElementsCount: focusableElements,
      hasSkipLinks: skipLinks > 0
    }
  }

  // Visual regression helpers
  async takeFullPageScreenshot(name: string) {
    await this.page.screenshot({
      path: `screenshots/${name}-full.png`,
      fullPage: true
    })
  }

  async takeComponentScreenshot(selector: string, name: string) {
    const element = this.page.locator(selector)
    await element.screenshot({
      path: `screenshots/${name}-component.png`
    })
  }
}