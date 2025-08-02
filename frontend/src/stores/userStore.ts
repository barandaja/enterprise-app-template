import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import type { 
  User, 
  UpdateProfileData, 
  ApiResponse, 
  LoadingState,
  AsyncState 
} from '../types';

// User preferences interface
interface UserPreferences {
  language: string;
  timezone: string;
  notifications: {
    email: boolean;
    push: boolean;
    sms: boolean;
  };
  privacy: {
    profileVisibility: 'public' | 'private' | 'friends';
    showEmail: boolean;
    showPhone: boolean;
  };
}

// User profile state with extended information
interface UserProfileState {
  // Core user data
  profile: User | null;
  preferences: UserPreferences | null;
  
  // Async state management
  profileState: AsyncState<User>;
  preferencesState: AsyncState<UserPreferences>;
  
  // Operation states
  updateProfileState: LoadingState;
  updatePreferencesState: LoadingState;
  uploadAvatarState: LoadingState;
  
  // Optimistic updates
  optimisticProfile: User | null;
  isOptimisticUpdate: boolean;
  
  // Cache management
  lastFetched: number | null;
  cacheExpiry: number; // in milliseconds
}

// User actions interface
interface UserActions {
  // Profile management
  fetchProfile: (userId?: string) => Promise<void>;
  updateProfile: (data: UpdateProfileData, optimistic?: boolean) => Promise<void>;
  uploadAvatar: (file: File) => Promise<void>;
  
  // Preferences management
  fetchPreferences: () => Promise<void>;
  updatePreferences: (preferences: Partial<UserPreferences>) => Promise<void>;
  
  // Cache management
  invalidateCache: () => void;
  isProfileCacheValid: () => boolean;
  refreshProfile: () => Promise<void>;
  
  // State management
  clearErrors: () => void;
  resetProfile: () => void;
  
  // Optimistic updates
  applyOptimisticUpdate: (profile: User) => void;
  revertOptimisticUpdate: () => void;
  
  // Utility methods
  getFullName: () => string;
  getInitials: () => string;
  hasPermission: (permission: string) => boolean;
}

// Combined store type
type UserStore = UserProfileState & UserActions;

// Default user preferences
const defaultPreferences: UserPreferences = {
  language: 'en',
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  notifications: {
    email: true,
    push: true,
    sms: false,
  },
  privacy: {
    profileVisibility: 'public',
    showEmail: false,
    showPhone: false,
  },
};

// Mock API service - replace with actual API calls
const userApi = {
  async getProfile(userId?: string): Promise<ApiResponse<User>> {
    // Mock implementation - replace with actual API call
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          success: true,
          data: {
            id: userId || '1',
            email: 'test@example.com',
            firstName: 'John',
            lastName: 'Doe',
            avatar: 'https://avatars.githubusercontent.com/u/1?v=4',
            role: 'user',
            isActive: true,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          },
        });
      }, 800);
    });
  },

  async updateProfile(data: UpdateProfileData): Promise<ApiResponse<User>> {
    // Mock implementation - replace with actual API call
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        if (Math.random() > 0.1) { // 90% success rate
          resolve({
            success: true,
            data: {
              id: '1',
              email: 'test@example.com',
              firstName: data.firstName || 'John',
              lastName: data.lastName || 'Doe',
              avatar: data.avatar || 'https://avatars.githubusercontent.com/u/1?v=4',
              role: 'user',
              isActive: true,
              createdAt: new Date().toISOString(),
              updatedAt: new Date().toISOString(),
            },
          });
        } else {
          reject(new Error('Profile update failed'));
        }
      }, 1200);
    });
  },

  async uploadAvatar(file: File): Promise<ApiResponse<{ url: string }>> {
    // Mock implementation - replace with actual file upload
    return new Promise((resolve) => {
      setTimeout(() => {
        const mockUrl = `https://avatars.githubusercontent.com/u/${Date.now()}?v=4`;
        resolve({
          success: true,
          data: { url: mockUrl },
        });
      }, 2000);
    });
  },

  async getPreferences(): Promise<ApiResponse<UserPreferences>> {
    // Mock implementation - replace with actual API call
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          success: true,
          data: defaultPreferences,
        });
      }, 600);
    });
  },

  async updatePreferences(preferences: Partial<UserPreferences>): Promise<ApiResponse<UserPreferences>> {
    // Mock implementation - replace with actual API call
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          success: true,
          data: { ...defaultPreferences, ...preferences },
        });
      }, 800);
    });
  },
};

// Create the user store
export const useUserStore = create<UserStore>()(
  devtools(
    persist(
      immer((set, get) => ({
        // Initial state
        profile: null,
        preferences: null,
        
        // Async states
        profileState: {
          data: null,
          loading: false,
          error: null,
        },
        preferencesState: {
          data: null,
          loading: false,
          error: null,
        },
        
        // Operation states
        updateProfileState: 'idle',
        updatePreferencesState: 'idle',
        uploadAvatarState: 'idle',
        
        // Optimistic updates
        optimisticProfile: null,
        isOptimisticUpdate: false,
        
        // Cache management
        lastFetched: null,
        cacheExpiry: 5 * 60 * 1000, // 5 minutes

        // Profile management actions
        fetchProfile: async (userId?: string) => {
          set((state) => {
            state.profileState.loading = true;
            state.profileState.error = null;
          });

          try {
            const response = await userApi.getProfile(userId);
            const profile = response.data;

            set((state) => {
              state.profile = profile;
              state.profileState.data = profile;
              state.profileState.loading = false;
              state.profileState.error = null;
              state.lastFetched = Date.now();
            });
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Failed to fetch profile';
            set((state) => {
              state.profileState.loading = false;
              state.profileState.error = new Error(errorMessage);
            });
            throw error;
          }
        },

        updateProfile: async (data: UpdateProfileData, optimistic = true) => {
          const currentProfile = get().profile;
          
          // Apply optimistic update if enabled and profile exists
          if (optimistic && currentProfile) {
            const optimisticProfile: User = {
              ...currentProfile,
              ...data,
              updatedAt: new Date().toISOString(),
            };
            
            set((state) => {
              state.optimisticProfile = optimisticProfile;
              state.isOptimisticUpdate = true;
            });
          }

          set((state) => {
            state.updateProfileState = 'loading';
          });

          try {
            const response = await userApi.updateProfile(data);
            const updatedProfile = response.data;

            set((state) => {
              state.profile = updatedProfile;
              state.profileState.data = updatedProfile;
              state.updateProfileState = 'success';
              state.optimisticProfile = null;
              state.isOptimisticUpdate = false;
              state.lastFetched = Date.now();
            });

            // Reset success state after delay
            setTimeout(() => {
              set((state) => {
                if (state.updateProfileState === 'success') {
                  state.updateProfileState = 'idle';
                }
              });
            }, 3000);
          } catch (error) {
            // Revert optimistic update on error
            set((state) => {
              state.updateProfileState = 'error';
              state.optimisticProfile = null;
              state.isOptimisticUpdate = false;
            });

            // Reset error state after delay
            setTimeout(() => {
              set((state) => {
                if (state.updateProfileState === 'error') {
                  state.updateProfileState = 'idle';
                }
              });
            }, 5000);

            throw error;
          }
        },

        uploadAvatar: async (file: File) => {
          set((state) => {
            state.uploadAvatarState = 'loading';
          });

          try {
            const response = await userApi.uploadAvatar(file);
            const { url } = response.data;

            // Update profile with new avatar
            await get().updateProfile({ avatar: url }, false);

            set((state) => {
              state.uploadAvatarState = 'success';
            });

            // Reset success state after delay
            setTimeout(() => {
              set((state) => {
                if (state.uploadAvatarState === 'success') {
                  state.uploadAvatarState = 'idle';
                }
              });
            }, 3000);
          } catch (error) {
            set((state) => {
              state.uploadAvatarState = 'error';
            });

            // Reset error state after delay
            setTimeout(() => {
              set((state) => {
                if (state.uploadAvatarState === 'error') {
                  state.uploadAvatarState = 'idle';
                }
              });
            }, 5000);

            throw error;
          }
        },

        // Preferences management
        fetchPreferences: async () => {
          set((state) => {
            state.preferencesState.loading = true;
            state.preferencesState.error = null;
          });

          try {
            const response = await userApi.getPreferences();
            const preferences = response.data;

            set((state) => {
              state.preferences = preferences;
              state.preferencesState.data = preferences;
              state.preferencesState.loading = false;
              state.preferencesState.error = null;
            });
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Failed to fetch preferences';
            set((state) => {
              state.preferencesState.loading = false;
              state.preferencesState.error = new Error(errorMessage);
            });
            throw error;
          }
        },

        updatePreferences: async (preferencesUpdate: Partial<UserPreferences>) => {
          set((state) => {
            state.updatePreferencesState = 'loading';
          });

          try {
            const response = await userApi.updatePreferences(preferencesUpdate);
            const updatedPreferences = response.data;

            set((state) => {
              state.preferences = updatedPreferences;
              state.preferencesState.data = updatedPreferences;
              state.updatePreferencesState = 'success';
            });

            // Reset success state after delay
            setTimeout(() => {
              set((state) => {
                if (state.updatePreferencesState === 'success') {
                  state.updatePreferencesState = 'idle';
                }
              });
            }, 3000);
          } catch (error) {
            set((state) => {
              state.updatePreferencesState = 'error';
            });

            // Reset error state after delay
            setTimeout(() => {
              set((state) => {
                if (state.updatePreferencesState === 'error') {
                  state.updatePreferencesState = 'idle';
                }
              });
            }, 5000);

            throw error;
          }
        },

        // Cache management
        invalidateCache: () => {
          set((state) => {
            state.lastFetched = null;
          });
        },

        isProfileCacheValid: (): boolean => {
          const { lastFetched, cacheExpiry } = get();
          if (!lastFetched) return false;
          return Date.now() - lastFetched < cacheExpiry;
        },

        refreshProfile: async () => {
          get().invalidateCache();
          await get().fetchProfile();
        },

        // State management
        clearErrors: () => {
          set((state) => {
            state.profileState.error = null;
            state.preferencesState.error = null;
          });
        },

        resetProfile: () => {
          set((state) => {
            state.profile = null;
            state.preferences = null;
            state.profileState = {
              data: null,
              loading: false,
              error: null,
            };
            state.preferencesState = {
              data: null,
              loading: false,
              error: null,
            };
            state.updateProfileState = 'idle';
            state.updatePreferencesState = 'idle';
            state.uploadAvatarState = 'idle';
            state.optimisticProfile = null;
            state.isOptimisticUpdate = false;
            state.lastFetched = null;
          });
        },

        // Optimistic updates
        applyOptimisticUpdate: (profile: User) => {
          set((state) => {
            state.optimisticProfile = profile;
            state.isOptimisticUpdate = true;
          });
        },

        revertOptimisticUpdate: () => {
          set((state) => {
            state.optimisticProfile = null;
            state.isOptimisticUpdate = false;
          });
        },

        // Utility methods
        getFullName: (): string => {
          const profile = get().optimisticProfile || get().profile;
          if (!profile) return '';
          return `${profile.firstName} ${profile.lastName}`.trim();
        },

        getInitials: (): string => {
          const profile = get().optimisticProfile || get().profile;
          if (!profile) return '';
          
          const firstInitial = profile.firstName?.charAt(0)?.toUpperCase() || '';
          const lastInitial = profile.lastName?.charAt(0)?.toUpperCase() || '';
          return `${firstInitial}${lastInitial}`;
        },

        hasPermission: (permission: string): boolean => {
          const profile = get().profile;
          if (!profile) return false;
          
          // Simple role-based permission system
          const rolePermissions: Record<string, string[]> = {
            admin: ['read', 'write', 'delete', 'manage_users', 'manage_settings'],
            moderator: ['read', 'write', 'moderate'],
            user: ['read', 'write_own'],
          };
          
          const userPermissions = rolePermissions[profile.role] || [];
          return userPermissions.includes(permission);
        },
      })),
      {
        name: 'user-storage',
        partialize: (state) => ({
          profile: state.profile,
          preferences: state.preferences,
          lastFetched: state.lastFetched,
        }),
      }
    ),
    {
      name: 'user-store',
    }
  )
);

// Selectors for performance optimization
export const useUserProfile = () => {
  const profile = useUserStore((state) => state.profile);
  const optimisticProfile = useUserStore((state) => state.optimisticProfile);
  const isOptimistic = useUserStore((state) => state.isOptimisticUpdate);
  
  return isOptimistic && optimisticProfile ? optimisticProfile : profile;
};

export const useUserPreferences = () => useUserStore((state) => state.preferences);
export const useUserProfileState = () => useUserStore((state) => state.profileState);
export const useUpdateProfileState = () => useUserStore((state) => state.updateProfileState);
export const useUploadAvatarState = () => useUserStore((state) => state.uploadAvatarState);

// User actions selectors
export const useUserActions = () => useUserStore((state) => ({
  fetchProfile: state.fetchProfile,
  updateProfile: state.updateProfile,
  uploadAvatar: state.uploadAvatar,
  fetchPreferences: state.fetchPreferences,
  updatePreferences: state.updatePreferences,
  refreshProfile: state.refreshProfile,
  clearErrors: state.clearErrors,
  resetProfile: state.resetProfile,
}));

// Utility selectors
export const useUserUtils = () => useUserStore((state) => ({
  getFullName: state.getFullName,
  getInitials: state.getInitials,
  hasPermission: state.hasPermission,
  isProfileCacheValid: state.isProfileCacheValid,
}));

// Composite hooks
export const useUserWithActions = () => {
  const profile = useUserProfile();
  const actions = useUserActions();
  const utils = useUserUtils();
  
  return {
    profile,
    ...actions,
    ...utils,
  };
};