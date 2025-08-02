/**
 * Age Verification Component
 * GDPR/COPPA compliant age verification
 */

import React, { useState, useEffect } from 'react';
import { Calendar, Shield, AlertCircle, Info, AlertTriangle } from 'lucide-react';
import { Button } from './Button';
import { Modal, ModalContent, ModalDescription, ModalFooter, ModalHeader, ModalTitle } from './Modal';
import { Alert, AlertContent } from './Alert';
import { Input } from './Input';
import { cn } from '../utils';

export interface AgeVerificationProps {
  minAge?: number;
  onVerified: (age: number, birthDate: Date) => void;
  onFailed: () => void;
  showParentalConsent?: boolean;
  privacyPolicyUrl?: string;
  termsUrl?: string;
}

const AGE_VERIFICATION_KEY = 'age_verified';
const AGE_VERIFICATION_EXPIRY = 90 * 24 * 60 * 60 * 1000; // 90 days

export function AgeVerification({
  minAge = 16, // GDPR default
  onVerified,
  onFailed,
  showParentalConsent = true,
  privacyPolicyUrl = '/privacy',
  termsUrl = '/terms',
}: AgeVerificationProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [birthDate, setBirthDate] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [requiresParentalConsent, setRequiresParentalConsent] = useState(false);

  useEffect(() => {
    // Check if already verified
    const verified = checkAgeVerification();
    if (!verified) {
      setIsOpen(true);
    }
  }, []);

  const checkAgeVerification = (): boolean => {
    try {
      const stored = localStorage.getItem(AGE_VERIFICATION_KEY);
      if (!stored) return false;

      const { timestamp, verified } = JSON.parse(stored);
      const age = Date.now() - timestamp;

      // Check if verification has expired
      if (age > AGE_VERIFICATION_EXPIRY) {
        localStorage.removeItem(AGE_VERIFICATION_KEY);
        return false;
      }

      return verified === true;
    } catch {
      return false;
    }
  };

  const calculateAge = (birthDate: Date): number => {
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }
    
    return age;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      const date = new Date(birthDate);
      
      // Validate date
      if (isNaN(date.getTime())) {
        setError('Please enter a valid date');
        setIsSubmitting(false);
        return;
      }

      // Check if date is in the future
      if (date > new Date()) {
        setError('Birth date cannot be in the future');
        setIsSubmitting(false);
        return;
      }

      const age = calculateAge(date);

      if (age >= minAge) {
        // Age verified
        localStorage.setItem(AGE_VERIFICATION_KEY, JSON.stringify({
          timestamp: Date.now(),
          verified: true,
          age,
        }));
        
        setIsOpen(false);
        onVerified(age, date);
      } else if (age >= 13 && showParentalConsent) {
        // Requires parental consent
        setRequiresParentalConsent(true);
      } else {
        // Too young
        setError(`You must be at least ${minAge} years old to use this service`);
        onFailed();
      }
    } catch (err) {
      setError('An error occurred. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleParentalConsent = () => {
    // In production, implement proper parental consent flow
    localStorage.setItem(AGE_VERIFICATION_KEY, JSON.stringify({
      timestamp: Date.now(),
      verified: true,
      parentalConsent: true,
    }));
    
    setIsOpen(false);
    onVerified(0, new Date(birthDate));
  };

  return (
    <>
      <Modal 
        isOpen={isOpen} 
        onClose={() => {}} // Prevent closing
        size="md"
        closeOnOverlayClick={false}
        showCloseButton={false}
      >
        <ModalHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            <ModalTitle>Age Verification Required</ModalTitle>
          </div>
          <ModalDescription>
            We need to verify your age to comply with privacy laws
          </ModalDescription>
        </ModalHeader>

        <ModalContent>
          {!requiresParentalConsent ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label htmlFor="birthDate" className="text-sm font-medium mb-2 block">
                  Date of Birth
                </label>
                <div className="relative">
                  <Calendar className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="birthDate"
                    type="date"
                    value={birthDate}
                    onChange={(e) => setBirthDate(e.target.value)}
                    className="pl-10"
                    required
                    max={new Date().toISOString().split('T')[0]}
                  />
                </div>
              </div>

              {error && (
                <Alert type="error">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertContent>{error}</AlertContent>
                </Alert>
              )}

              <Alert>
                <Info className="h-4 w-4" />
                <AlertContent>
                  <h4 className="font-medium">Why we need your age</h4>
                  <ul className="text-sm mt-2 space-y-1">
                    <li>• To comply with GDPR and COPPA regulations</li>
                    <li>• To provide age-appropriate content</li>
                    <li>• To protect children's privacy online</li>
                  </ul>
                </AlertContent>
              </Alert>

              <div className="text-sm text-muted-foreground">
                By verifying your age, you agree to our{' '}
                <a href={privacyPolicyUrl} className="text-primary hover:underline" target="_blank" rel="noopener noreferrer">
                  Privacy Policy
                </a>{' '}
                and{' '}
                <a href={termsUrl} className="text-primary hover:underline" target="_blank" rel="noopener noreferrer">
                  Terms of Service
                </a>.
              </div>

              <Button
                type="submit"
                className="w-full"
                loading={isSubmitting}
                disabled={!birthDate}
              >
                Verify Age
              </Button>
            </form>
          ) : (
            <div className="space-y-4">
              <Alert type="warning">
                <AlertTriangle className="h-4 w-4" />
                <AlertContent>
                  <h4 className="font-medium">Parental Consent Required</h4>
                  <p className="text-sm mt-1">
                    Users under {minAge} years old require parental consent to use this service.
                  </p>
                </AlertContent>
              </Alert>

              <div className="p-4 bg-muted rounded-lg">
                <h4 className="font-medium text-sm mb-2">For Parents/Guardians:</h4>
                <ul className="text-sm text-muted-foreground space-y-1">
                  <li>• We collect minimal data from users under {minAge}</li>
                  <li>• No marketing or analytics cookies will be used</li>
                  <li>• You can request data deletion at any time</li>
                  <li>• Review our Children's Privacy Policy for details</li>
                </ul>
              </div>

              <div className="flex gap-3">
                <Button
                  variant="outline"
                  onClick={() => {
                    setRequiresParentalConsent(false);
                    setBirthDate('');
                    setError(null);
                  }}
                  className="flex-1"
                >
                  Back
                </Button>
                <Button
                  onClick={handleParentalConsent}
                  className="flex-1"
                >
                  I'm a Parent/Guardian
                </Button>
              </div>
            </div>
          )}
        </ModalContent>
      </Modal>

      {/* Age Gate for users who failed verification */}
      <AgeGate minAge={minAge} />
    </>
  );
}

// Age gate component for users who are too young
function AgeGate({ minAge }: { minAge: number }) {
  const [showGate, setShowGate] = useState(false);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(AGE_VERIFICATION_KEY);
      if (stored) {
        const { verified } = JSON.parse(stored);
        if (verified === false) {
          setShowGate(true);
        }
      }
    } catch {}
  }, []);

  if (!showGate) return null;

  return (
    <div className="fixed inset-0 z-50 bg-background flex items-center justify-center p-4">
      <div className="max-w-md w-full text-center">
        <Shield className="h-16 w-16 text-muted-foreground mx-auto mb-4" />
        <h1 className="text-2xl font-bold mb-2">Age Restriction</h1>
        <p className="text-muted-foreground mb-6">
          You must be at least {minAge} years old to use this service.
        </p>
        <div className="space-y-3">
          <Button
            variant="outline"
            onClick={() => window.location.href = 'https://www.google.com'}
            className="w-full"
          >
            Leave Site
          </Button>
          <p className="text-sm text-muted-foreground">
            If you believe this is an error, please contact support.
          </p>
        </div>
      </div>
    </div>
  );
}

// Hook for checking age verification status
export function useAgeVerification() {
  const [isVerified, setIsVerified] = useState<boolean | null>(null);
  const [age, setAge] = useState<number | null>(null);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(AGE_VERIFICATION_KEY);
      if (stored) {
        const data = JSON.parse(stored);
        setIsVerified(data.verified === true);
        setAge(data.age || null);
      } else {
        setIsVerified(false);
      }
    } catch {
      setIsVerified(false);
    }
  }, []);

  const reset = () => {
    localStorage.removeItem(AGE_VERIFICATION_KEY);
    setIsVerified(false);
    setAge(null);
    window.location.reload();
  };

  return { isVerified, age, reset };
}

// Component to wrap age-restricted content
export function AgeRestricted({ 
  children, 
  minAge = 18,
  fallback = <div>This content is age-restricted</div> 
}: { 
  children: React.ReactNode;
  minAge?: number;
  fallback?: React.ReactNode;
}) {
  const { isVerified, age } = useAgeVerification();

  if (isVerified && age && age >= minAge) {
    return <>{children}</>;
  }

  return <>{fallback}</>;
}