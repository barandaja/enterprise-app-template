/**
 * Secure password input component with strength meter and validation
 */

import React, { useState, forwardRef } from 'react';
import { Eye, EyeOff, RefreshCw, Copy, Check } from 'lucide-react';
import { Input, type InputProps } from './Input';
import { PasswordStrengthMeter } from './PasswordStrengthMeter';
import { Button } from './Button';
import { 
  generateSecurePassword, 
  DEFAULT_PASSWORD_REQUIREMENTS,
  type PasswordRequirements 
} from '../security/passwordValidation';
import { cn } from '../utils';
import { toast } from 'react-hot-toast';

export interface SecurePasswordInputProps extends Omit<InputProps, 'type' | 'rightIcon'> {
  showStrengthMeter?: boolean;
  showRequirements?: boolean;
  showFeedback?: boolean;
  showGenerator?: boolean;
  requirements?: PasswordRequirements;
  userInfo?: {
    email?: string;
    username?: string;
    firstName?: string;
    lastName?: string;
  };
  onPasswordGenerated?: (password: string) => void;
  strengthMeterClassName?: string;
}

export const SecurePasswordInput = forwardRef<HTMLInputElement, SecurePasswordInputProps>(
  (
    {
      showStrengthMeter = true,
      showRequirements = true,
      showFeedback = true,
      showGenerator = false,
      requirements = DEFAULT_PASSWORD_REQUIREMENTS,
      userInfo,
      onPasswordGenerated,
      strengthMeterClassName,
      value,
      onChange,
      className,
      error,
      ...props
    },
    ref
  ) => {
    const [showPassword, setShowPassword] = useState(false);
    const [generatedPassword, setGeneratedPassword] = useState<string | null>(null);
    const [copied, setCopied] = useState(false);

    const handleToggleVisibility = () => {
      setShowPassword(!showPassword);
    };

    const handleGeneratePassword = () => {
      const newPassword = generateSecurePassword(16, {
        includeUppercase: requirements.requireUppercase,
        includeLowercase: requirements.requireLowercase,
        includeNumbers: requirements.requireNumbers,
        includeSpecialChars: requirements.requireSpecialChars,
        excludeAmbiguous: true,
      });

      setGeneratedPassword(newPassword);
      setShowPassword(true);

      // Update the input value
      if (onChange) {
        const event = {
          target: { value: newPassword },
        } as React.ChangeEvent<HTMLInputElement>;
        onChange(event);
      }

      if (onPasswordGenerated) {
        onPasswordGenerated(newPassword);
      }

      toast.success('Secure password generated!');
    };

    const handleCopyPassword = async () => {
      const passwordToCopy = generatedPassword || (value as string);
      if (!passwordToCopy) return;

      try {
        await navigator.clipboard.writeText(passwordToCopy);
        setCopied(true);
        toast.success('Password copied to clipboard!');
        
        // Reset copied state after 2 seconds
        setTimeout(() => setCopied(false), 2000);
      } catch (err) {
        toast.error('Failed to copy password');
      }
    };

    const passwordValue = value as string || '';

    return (
      <div className="space-y-3">
        <div className="relative">
          <Input
            ref={ref}
            type={showPassword ? 'text' : 'password'}
            value={value}
            onChange={onChange}
            error={error}
            className={className}
            rightIcon={
              <div className="flex items-center space-x-1">
                {showGenerator && generatedPassword && (
                  <button
                    type="button"
                    onClick={handleCopyPassword}
                    className="p-1 text-muted-foreground hover:text-foreground transition-colors"
                    title="Copy password"
                  >
                    {copied ? (
                      <Check className="h-4 w-4 text-green-500" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </button>
                )}
                <button
                  type="button"
                  onClick={handleToggleVisibility}
                  className="p-1 text-muted-foreground hover:text-foreground transition-colors"
                  title={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
            }
            {...props}
          />
        </div>

        {showGenerator && (
          <div className="flex items-center justify-between">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleGeneratePassword}
              className="text-xs"
            >
              <RefreshCw className="h-3 w-3 mr-1" />
              Generate Strong Password
            </Button>
            {generatedPassword && passwordValue === generatedPassword && (
              <span className="text-xs text-green-600">
                Using generated password
              </span>
            )}
          </div>
        )}

        {showStrengthMeter && passwordValue && (
          <PasswordStrengthMeter
            password={passwordValue}
            requirements={requirements}
            userInfo={userInfo}
            showFeedback={showFeedback}
            showRequirements={showRequirements}
            className={strengthMeterClassName}
          />
        )}
      </div>
    );
  }
);

SecurePasswordInput.displayName = 'SecurePasswordInput';

// Password confirmation input that validates against the original password
export interface PasswordConfirmationInputProps extends Omit<InputProps, 'type' | 'error'> {
  password: string;
  confirmPassword: string;
  onConfirmPasswordChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
}

export const PasswordConfirmationInput = forwardRef<HTMLInputElement, PasswordConfirmationInputProps>(
  ({ password, confirmPassword, onConfirmPasswordChange, ...props }, ref) => {
    const [showPassword, setShowPassword] = useState(false);
    
    // Calculate error state
    const hasError = confirmPassword && password !== confirmPassword;
    const error = hasError ? 'Passwords do not match' : undefined;

    return (
      <Input
        ref={ref}
        type={showPassword ? 'text' : 'password'}
        value={confirmPassword}
        onChange={onConfirmPasswordChange}
        error={error}
        rightIcon={
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="p-1 text-muted-foreground hover:text-foreground transition-colors"
            title={showPassword ? 'Hide password' : 'Show password'}
          >
            {showPassword ? (
              <EyeOff className="h-4 w-4" />
            ) : (
              <Eye className="h-4 w-4" />
            )}
          </button>
        }
        {...props}
      />
    );
  }
);

PasswordConfirmationInput.displayName = 'PasswordConfirmationInput';