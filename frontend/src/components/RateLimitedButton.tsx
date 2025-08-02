/**
 * Rate-limited button component
 * Prevents rapid clicking and shows feedback when rate limited
 */

import React, { useState, useCallback, useEffect } from 'react';
import { AlertCircle, Clock } from 'lucide-react';
import { Button, type ButtonProps } from './Button';
import { useRateLimit, RATE_LIMITS } from '../security/rateLimiter';
import { cn } from '../utils';

export interface RateLimitedButtonProps extends ButtonProps {
  rateLimitConfig?: typeof RATE_LIMITS[keyof typeof RATE_LIMITS];
  onRateLimitExceeded?: (retriesAfter: number) => void;
  showCountdown?: boolean;
  customLimitedMessage?: string;
}

export function RateLimitedButton({
  onClick,
  disabled,
  children,
  rateLimitConfig = RATE_LIMITS.FORM_SUBMISSION,
  onRateLimitExceeded,
  showCountdown = true,
  customLimitedMessage,
  className,
  ...props
}: RateLimitedButtonProps) {
  const { checkLimit, isLimited, reset } = useRateLimit(rateLimitConfig);
  const [retriesAfter, setRetriesAfter] = useState<number>(0);
  const [countdown, setCountdown] = useState<number>(0);

  // Update countdown timer
  useEffect(() => {
    if (countdown <= 0) return;

    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          setRetriesAfter(0);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [countdown]);

  const handleClick = useCallback(
    async (e: React.MouseEvent<HTMLButtonElement>) => {
      e.preventDefault();
      
      const result = checkLimit();
      
      if (!result.allowed) {
        if (result.retriesAfter) {
          setRetriesAfter(result.retriesAfter);
          setCountdown(result.retriesAfter);
          onRateLimitExceeded?.(result.retriesAfter);
        }
        return;
      }

      // Call original onClick handler
      if (onClick) {
        await onClick(e);
      }
    },
    [checkLimit, onClick, onRateLimitExceeded]
  );

  const isButtonDisabled = disabled || isLimited || retriesAfter > 0;

  const renderContent = () => {
    if (retriesAfter > 0 && showCountdown) {
      return (
        <span className="flex items-center space-x-2">
          <Clock className="h-4 w-4" />
          <span>
            {customLimitedMessage || `Try again in ${countdown}s`}
          </span>
        </span>
      );
    }

    return children;
  };

  return (
    <>
      <Button
        {...props}
        onClick={handleClick}
        disabled={isButtonDisabled}
        className={cn(
          className,
          retriesAfter > 0 && 'cursor-not-allowed'
        )}
      >
        {renderContent()}
      </Button>
      
      {retriesAfter > 0 && !showCountdown && (
        <div className="mt-2 flex items-center space-x-2 text-sm text-destructive">
          <AlertCircle className="h-4 w-4" />
          <span>
            {customLimitedMessage || 
              `Too many attempts. Please try again in ${countdown} seconds.`}
          </span>
        </div>
      )}
    </>
  );
}

// Hook for managing rate-limited forms
export function useRateLimitedForm(
  rateLimitConfig = RATE_LIMITS.FORM_SUBMISSION
) {
  const { checkLimit, isLimited, reset } = useRateLimit(rateLimitConfig);
  const [isRateLimited, setIsRateLimited] = useState(false);
  const [retriesAfter, setRetriesAfter] = useState<number>(0);

  const checkFormSubmission = useCallback(() => {
    const result = checkLimit();
    
    if (!result.allowed) {
      setIsRateLimited(true);
      setRetriesAfter(result.retriesAfter || 0);
      return false;
    }
    
    setIsRateLimited(false);
    setRetriesAfter(0);
    return true;
  }, [checkLimit]);

  const resetLimit = useCallback(() => {
    reset();
    setIsRateLimited(false);
    setRetriesAfter(0);
  }, [reset]);

  return {
    isRateLimited,
    retriesAfter,
    checkFormSubmission,
    resetLimit,
  };
}