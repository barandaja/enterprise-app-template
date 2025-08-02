/**
 * Password strength meter component
 * Provides visual feedback on password strength and requirements
 */

import React from 'react';
import { Check, X, AlertCircle } from 'lucide-react';
import { 
  validatePassword, 
  DEFAULT_PASSWORD_REQUIREMENTS,
  type PasswordRequirements,
  type PasswordStrength 
} from '../security/passwordValidation';
import { cn } from '../utils';

export interface PasswordStrengthMeterProps {
  password: string;
  requirements?: PasswordRequirements;
  userInfo?: { 
    email?: string; 
    username?: string; 
    firstName?: string; 
    lastName?: string; 
  };
  showFeedback?: boolean;
  showRequirements?: boolean;
  className?: string;
}

export function PasswordStrengthMeter({
  password,
  requirements = DEFAULT_PASSWORD_REQUIREMENTS,
  userInfo,
  showFeedback = true,
  showRequirements = true,
  className = '',
}: PasswordStrengthMeterProps) {
  const strength = validatePassword(password, requirements, userInfo);

  // Calculate which requirements are met
  const requirementsMet = {
    length: password.length >= requirements.minLength,
    uppercase: !requirements.requireUppercase || /[A-Z]/.test(password),
    lowercase: !requirements.requireLowercase || /[a-z]/.test(password),
    numbers: !requirements.requireNumbers || /\d/.test(password),
    special: !requirements.requireSpecialChars || /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
  };

  // Get color based on strength
  const getStrengthColor = () => {
    switch (strength.strength) {
      case 'very-weak': return 'bg-destructive';
      case 'weak': return 'bg-orange-500';
      case 'fair': return 'bg-yellow-500';
      case 'strong': return 'bg-green-500';
      case 'very-strong': return 'bg-green-600';
      default: return 'bg-muted';
    }
  };

  // Get text color based on strength
  const getStrengthTextColor = () => {
    switch (strength.strength) {
      case 'very-weak': return 'text-destructive';
      case 'weak': return 'text-orange-500';
      case 'fair': return 'text-yellow-500';
      case 'strong': return 'text-green-500';
      case 'very-strong': return 'text-green-600';
      default: return 'text-muted-foreground';
    }
  };

  // Calculate progress percentage
  const progressPercentage = (strength.score / 5) * 100;

  if (!password) {
    return null;
  }

  return (
    <div className={cn('space-y-3', className)}>
      {/* Strength meter bar */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-sm font-medium text-foreground">
            Password Strength
          </span>
          <span className={cn('text-sm font-medium capitalize', getStrengthTextColor())}>
            {strength.strength.replace('-', ' ')}
          </span>
        </div>
        
        <div className="relative h-2 w-full overflow-hidden rounded-full bg-muted">
          <div
            className={cn(
              'h-full transition-all duration-300 ease-out',
              getStrengthColor()
            )}
            style={{ width: `${progressPercentage}%` }}
          />
        </div>
      </div>

      {/* Requirements checklist */}
      {showRequirements && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-foreground">Requirements</h4>
          <ul className="space-y-1">
            <RequirementItem
              met={requirementsMet.length}
              text={`At least ${requirements.minLength} characters`}
            />
            {requirements.requireUppercase && (
              <RequirementItem
                met={requirementsMet.uppercase}
                text="One uppercase letter"
              />
            )}
            {requirements.requireLowercase && (
              <RequirementItem
                met={requirementsMet.lowercase}
                text="One lowercase letter"
              />
            )}
            {requirements.requireNumbers && (
              <RequirementItem
                met={requirementsMet.numbers}
                text="One number"
              />
            )}
            {requirements.requireSpecialChars && (
              <RequirementItem
                met={requirementsMet.special}
                text="One special character (!@#$%...)"
              />
            )}
          </ul>
        </div>
      )}

      {/* Feedback messages */}
      {showFeedback && strength.feedback.length > 0 && (
        <div className="space-y-1">
          {strength.feedback.map((feedback, index) => (
            <div
              key={index}
              className="flex items-start space-x-2 text-sm text-destructive"
            >
              <AlertCircle className="h-4 w-4 flex-shrink-0 mt-0.5" />
              <span>{feedback}</span>
            </div>
          ))}
        </div>
      )}

      {/* Success message */}
      {showFeedback && strength.isAcceptable && strength.feedback.length === 0 && (
        <div className="flex items-center space-x-2 text-sm text-green-600">
          <Check className="h-4 w-4" />
          <span>Strong password! Good job!</span>
        </div>
      )}
    </div>
  );
}

interface RequirementItemProps {
  met: boolean;
  text: string;
}

function RequirementItem({ met, text }: RequirementItemProps) {
  return (
    <li className="flex items-center space-x-2 text-sm">
      {met ? (
        <Check className="h-4 w-4 text-green-500" />
      ) : (
        <X className="h-4 w-4 text-muted-foreground" />
      )}
      <span className={cn(
        'transition-colors',
        met ? 'text-foreground' : 'text-muted-foreground'
      )}>
        {text}
      </span>
    </li>
  );
}

// Export a hook for easy integration with forms
export function usePasswordStrengthMeter(
  requirements?: PasswordRequirements
): {
  validatePassword: (password: string, userInfo?: any) => PasswordStrength;
  getValidationRules: () => any;
} {
  return {
    validatePassword: (password: string, userInfo?: any) => 
      validatePassword(password, requirements, userInfo),
    getValidationRules: () => ({
      required: 'Password is required',
      minLength: {
        value: requirements?.minLength || DEFAULT_PASSWORD_REQUIREMENTS.minLength,
        message: `Password must be at least ${requirements?.minLength || DEFAULT_PASSWORD_REQUIREMENTS.minLength} characters`,
      },
      validate: (value: string) => {
        const result = validatePassword(value, requirements);
        return result.isAcceptable || result.feedback.join('. ');
      },
    }),
  };
}