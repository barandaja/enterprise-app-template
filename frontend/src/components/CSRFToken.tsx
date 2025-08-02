/**
 * CSRF Token component for forms
 * Provides a hidden input field with the current CSRF token
 */

import React from 'react';
import { useCSRFToken } from '../security/csrf';

/**
 * Hidden CSRF token input for forms
 * 
 * @example
 * <form onSubmit={handleSubmit}>
 *   <CSRFToken />
 *   <input type="text" name="username" />
 *   <button type="submit">Submit</button>
 * </form>
 */
export function CSRFToken() {
  const { token } = useCSRFToken();
  
  return (
    <input 
      type="hidden" 
      name="csrf_token" 
      value={token}
      readOnly
    />
  );
}

/**
 * Hook to get CSRF token for manual form submissions
 * 
 * @example
 * const { token, headerName } = useCSRFToken();
 * 
 * const formData = new FormData();
 * formData.append('csrf_token', token);
 * 
 * // Or for headers
 * fetch('/api/endpoint', {
 *   method: 'POST',
 *   headers: {
 *     [headerName]: token
 *   }
 * });
 */
export { useCSRFToken } from '../security/csrf';