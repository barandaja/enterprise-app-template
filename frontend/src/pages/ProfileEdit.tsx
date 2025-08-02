import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { 
  User, 
  Mail, 
  Phone,
  MapPin,
  Building,
  Briefcase,
  Save,
  X,
  AlertCircle,
  Camera
} from 'lucide-react';
import { PageProps } from '../types';
import { SecureFileUpload } from '../components/SecureFileUpload';
import { toast } from 'react-hot-toast';

// Form validation schema
const profileEditSchema = z.object({
  firstName: z.string().min(1, 'First name is required').max(50, 'First name must be less than 50 characters'),
  lastName: z.string().min(1, 'Last name is required').max(50, 'Last name must be less than 50 characters'),
  email: z.string().email('Invalid email address'),
  phone: z.string().optional().refine((val) => !val || /^[+]?[(]?[0-9]{3}[)]?[-\s.]?[0-9]{3}[-\s.]?[0-9]{4,6}$/.test(val), {
    message: 'Invalid phone number format',
  }),
  location: z.string().optional().max(100, 'Location must be less than 100 characters'),
  bio: z.string().optional().max(500, 'Bio must be less than 500 characters'),
  department: z.string().optional().max(50, 'Department must be less than 50 characters'),
  position: z.string().optional().max(50, 'Position must be less than 50 characters'),
});

type ProfileEditFormData = z.infer<typeof profileEditSchema>;

// Mock user data - in a real app, this would come from a store or API
const mockUser = {
  id: '1',
  firstName: 'John',
  lastName: 'Doe',
  email: 'john.doe@example.com',
  avatar: '',
  phone: '+1 (555) 123-4567',
  location: 'San Francisco, CA',
  bio: 'Senior Frontend Developer with 5+ years of experience building modern web applications. Passionate about React, TypeScript, and creating exceptional user experiences.',
  department: 'Engineering',
  position: 'Senior Frontend Developer',
};

function getInitials(firstName: string, lastName: string) {
  return `${firstName.charAt(0)}${lastName.charAt(0)}`.toUpperCase();
}

function ProfileEdit({ className }: PageProps) {
  const navigate = useNavigate();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState(false);
  const [profilePicture, setProfilePicture] = useState<File | null>(null);
  const [uploadingPicture, setUploadingPicture] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isDirty },
    watch,
  } = useForm<ProfileEditFormData>({
    resolver: zodResolver(profileEditSchema),
    defaultValues: {
      firstName: mockUser.firstName,
      lastName: mockUser.lastName,
      email: mockUser.email,
      phone: mockUser.phone,
      location: mockUser.location,
      bio: mockUser.bio,
      department: mockUser.department,
      position: mockUser.position,
    },
  });

  const watchedFirstName = watch('firstName');
  const watchedLastName = watch('lastName');

  const onSubmit = async (data: ProfileEditFormData) => {
    try {
      setIsSubmitting(true);
      setSubmitError(null);
      
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // In a real app, you would:
      // - Call the API to update the profile
      // - Update the global state/store
      // - Handle errors appropriately
      
      console.log('Profile update data:', data);
      setSubmitSuccess(true);
      
      // Redirect after a short delay
      setTimeout(() => {
        navigate('/profile');
      }, 1000);
    } catch (error) {
      setSubmitError('Failed to update profile. Please try again.');
      console.error('Profile update error:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCancel = () => {
    if (isDirty) {
      const confirmLeave = window.confirm('You have unsaved changes. Are you sure you want to leave?');
      if (!confirmLeave) return;
    }
    navigate('/profile');
  };

  return (
    <div className="container py-8 max-w-4xl">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-3xl font-bold text-foreground">Edit Profile</h1>
          <button
            onClick={handleCancel}
            className="btn-ghost"
            disabled={isSubmitting}
          >
            <X className="h-4 w-4" />
            Cancel
          </button>
        </div>
        <p className="text-muted-foreground">
          Update your personal information and account details
        </p>
      </div>

      {/* Success Message */}
      {submitSuccess && (
        <div className="alert-success mb-6 animate-in">
          <div className="flex items-center space-x-2">
            <AlertCircle className="h-4 w-4" />
            <span>Profile updated successfully! Redirecting...</span>
          </div>
        </div>
      )}

      {/* Error Message */}
      {submitError && (
        <div className="alert-error mb-6 animate-in">
          <div className="flex items-center space-x-2">
            <AlertCircle className="h-4 w-4" />
            <span>{submitError}</span>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* Profile Picture */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Profile Picture</h2>
            <p className="card-description">
              Upload a profile picture or use your initials
            </p>
          </div>
          <div className="card-content">
            <div className="flex items-center space-x-6">
              {mockUser.avatar ? (
                <img
                  src={mockUser.avatar}
                  alt="Profile"
                  className="w-24 h-24 rounded-full object-cover border-4 border-background shadow-lg"
                />
              ) : (
                <div className="w-24 h-24 rounded-full bg-primary/10 flex items-center justify-center border-4 border-background shadow-lg">
                  <span className="text-2xl font-bold text-primary">
                    {getInitials(watchedFirstName || 'J', watchedLastName || 'D')}
                  </span>
                </div>
              )}
              <div className="flex-1">
                <SecureFileUpload
                  accept="image/jpeg,image/png,image/gif,image/webp"
                  maxSize={5 * 1024 * 1024} // 5MB
                  maxFiles={1}
                  allowedTypes={['image/jpeg', 'image/png', 'image/gif', 'image/webp']}
                  allowedExtensions={['jpg', 'jpeg', 'png', 'gif', 'webp']}
                  onUpload={async (files) => {
                    setUploadingPicture(true);
                    try {
                      // In a real app, this would upload to a server
                      // For now, we'll just store the file locally
                      setProfilePicture(files[0]);
                      
                      // Create a preview URL
                      const reader = new FileReader();
                      reader.onloadend = () => {
                        // Here you would typically update the user's avatar URL
                        mockUser.avatar = reader.result as string;
                      };
                      reader.readAsDataURL(files[0]);
                      
                      toast.success('Profile picture uploaded successfully!');
                    } catch (error) {
                      toast.error('Failed to upload profile picture');
                      throw error;
                    } finally {
                      setUploadingPicture(false);
                    }
                  }}
                  onError={(error) => {
                    toast.error(error);
                  }}
                  disabled={isSubmitting || uploadingPicture}
                  helpText="JPG, PNG, GIF or WebP. Maximum file size: 5MB"
                />
              </div>
            </div>
          </div>
        </div>

        {/* Personal Information */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Personal Information</h2>
            <p className="card-description">
              Update your personal details
            </p>
          </div>
          <div className="card-content">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="firstName" className="label">
                  First Name
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <input
                    id="firstName"
                    type="text"
                    className={`input pl-10 ${errors.firstName ? 'border-destructive' : ''}`}
                    {...register('firstName')}
                    disabled={isSubmitting}
                  />
                </div>
                {errors.firstName && (
                  <p className="text-xs text-error mt-1">{errors.firstName.message}</p>
                )}
              </div>

              <div>
                <label htmlFor="lastName" className="label">
                  Last Name
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <input
                    id="lastName"
                    type="text"
                    className={`input pl-10 ${errors.lastName ? 'border-destructive' : ''}`}
                    {...register('lastName')}
                    disabled={isSubmitting}
                  />
                </div>
                {errors.lastName && (
                  <p className="text-xs text-error mt-1">{errors.lastName.message}</p>
                )}
              </div>

              <div>
                <label htmlFor="email" className="label">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <input
                    id="email"
                    type="email"
                    className={`input pl-10 ${errors.email ? 'border-destructive' : ''}`}
                    {...register('email')}
                    disabled={isSubmitting}
                  />
                </div>
                {errors.email && (
                  <p className="text-xs text-error mt-1">{errors.email.message}</p>
                )}
              </div>

              <div>
                <label htmlFor="phone" className="label">
                  Phone Number
                </label>
                <div className="relative">
                  <Phone className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <input
                    id="phone"
                    type="tel"
                    className={`input pl-10 ${errors.phone ? 'border-destructive' : ''}`}
                    {...register('phone')}
                    disabled={isSubmitting}
                  />
                </div>
                {errors.phone && (
                  <p className="text-xs text-error mt-1">{errors.phone.message}</p>
                )}
              </div>

              <div className="md:col-span-2">
                <label htmlFor="location" className="label">
                  Location
                </label>
                <div className="relative">
                  <MapPin className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <input
                    id="location"
                    type="text"
                    className={`input pl-10 ${errors.location ? 'border-destructive' : ''}`}
                    {...register('location')}
                    disabled={isSubmitting}
                  />
                </div>
                {errors.location && (
                  <p className="text-xs text-error mt-1">{errors.location.message}</p>
                )}
              </div>

              <div className="md:col-span-2">
                <label htmlFor="bio" className="label">
                  Bio
                </label>
                <textarea
                  id="bio"
                  rows={4}
                  className={`input resize-none ${errors.bio ? 'border-destructive' : ''}`}
                  {...register('bio')}
                  disabled={isSubmitting}
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Brief description for your profile (max 500 characters)
                </p>
                {errors.bio && (
                  <p className="text-xs text-error mt-1">{errors.bio.message}</p>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Work Information */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Work Information</h2>
            <p className="card-description">
              Update your professional details
            </p>
          </div>
          <div className="card-content">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="department" className="label">
                  Department
                </label>
                <div className="relative">
                  <Building className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <input
                    id="department"
                    type="text"
                    className={`input pl-10 ${errors.department ? 'border-destructive' : ''}`}
                    {...register('department')}
                    disabled={isSubmitting}
                  />
                </div>
                {errors.department && (
                  <p className="text-xs text-error mt-1">{errors.department.message}</p>
                )}
              </div>

              <div>
                <label htmlFor="position" className="label">
                  Position
                </label>
                <div className="relative">
                  <Briefcase className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                  <input
                    id="position"
                    type="text"
                    className={`input pl-10 ${errors.position ? 'border-destructive' : ''}`}
                    {...register('position')}
                    disabled={isSubmitting}
                  />
                </div>
                {errors.position && (
                  <p className="text-xs text-error mt-1">{errors.position.message}</p>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Form Actions */}
        <div className="flex items-center justify-end space-x-3">
          <button
            type="button"
            onClick={handleCancel}
            className="btn-outline"
            disabled={isSubmitting}
          >
            Cancel
          </button>
          <button
            type="submit"
            className="btn-primary"
            disabled={isSubmitting || !isDirty}
          >
            <Save className="h-4 w-4" />
            {isSubmitting ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </form>
    </div>
  );
}

export default ProfileEdit;