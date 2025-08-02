// Common types used throughout the application

export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  role: UserRole;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export type UserRole = 'admin' | 'user' | 'moderator';

export interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  token: string | null;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

export interface UpdateProfileData {
  firstName?: string;
  lastName?: string;
  avatar?: string;
}

// API Response types
export interface ApiResponse<T = unknown> {
  success: boolean;
  data: T;
  message?: string;
}

export interface ApiError {
  success: false;
  message: string;
  errors?: Record<string, string[]>;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Form types
export interface FormFieldError {
  message: string;
}

export interface FormState<T = Record<string, unknown>> {
  values: T;
  errors: Record<keyof T, FormFieldError | undefined>;
  touched: Record<keyof T, boolean>;
  isSubmitting: boolean;
  isValid: boolean;
}

// UI Component types
export interface ButtonProps {
  children: React.ReactNode;
  variant?: 'primary' | 'secondary' | 'outline' | 'ghost' | 'destructive';
  size?: 'sm' | 'md' | 'lg' | 'icon';
  disabled?: boolean;
  loading?: boolean;
  onClick?: () => void;
  type?: 'button' | 'submit' | 'reset';
  className?: string;
}

export interface InputProps {
  id?: string;
  name?: string;
  type?: 'text' | 'email' | 'password' | 'number' | 'tel' | 'url';
  placeholder?: string;
  value?: string;
  defaultValue?: string;
  disabled?: boolean;
  required?: boolean;
  className?: string;
  onChange?: (event: React.ChangeEvent<HTMLInputElement>) => void;
  onBlur?: (event: React.FocusEvent<HTMLInputElement>) => void;
  onFocus?: (event: React.FocusEvent<HTMLInputElement>) => void;
}

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps {
  id?: string;
  name?: string;
  value?: string;
  defaultValue?: string;
  placeholder?: string;
  disabled?: boolean;
  required?: boolean;
  options: SelectOption[];
  className?: string;
  onChange?: (value: string) => void;
}

export interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  className?: string;
}

export interface AlertProps {
  variant?: 'default' | 'destructive' | 'success' | 'warning' | 'info';
  title?: string;
  children: React.ReactNode;
  className?: string;
}

// Navigation types
export interface NavItem {
  label: string;
  href: string;
  icon?: React.ComponentType<{ className?: string }>;
  isActive?: boolean;
  disabled?: boolean;
}

export interface BreadcrumbItem {
  label: string;
  href?: string;
}

// Theme types
export type Theme = 'light' | 'dark' | 'system';

export interface ThemeState {
  theme: Theme;
  systemTheme: 'light' | 'dark';
  resolvedTheme: 'light' | 'dark';
}

// Utility types
export type LoadingState = 'idle' | 'loading' | 'success' | 'error';

export interface AsyncState<T = unknown, E = Error> {
  data: T | null;
  loading: boolean;
  error: E | null;
}

// Page props types
export interface PageProps {
  className?: string;
  children?: React.ReactNode;
}

// Route types
export interface RouteConfig {
  path: string;
  element: React.ComponentType<PageProps>;
  title?: string;
  requiresAuth?: boolean;
  roles?: UserRole[];
}

// Store types (for Zustand)
export interface StoreState {
  // Common store state interface
  isLoading: boolean;
  error: string | null;
}

export interface AuthStore extends StoreState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => void;
  updateProfile: (data: UpdateProfileData) => Promise<void>;
  clearError: () => void;
}

export interface ThemeStore {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
}

// Event types
export interface CustomEvent<T = unknown> {
  type: string;
  payload?: T;
  timestamp: number;
}

// File upload types
export interface FileUpload {
  file: File;
  progress: number;
  status: 'pending' | 'uploading' | 'success' | 'error';
  url?: string;
  error?: string;
}

// Search and filter types
export interface SearchParams {
  query?: string;
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
  filters?: Record<string, unknown>;
}

export interface SortOption {
  key: string;
  label: string;
  order: 'asc' | 'desc';
}

// Date and time types
export type DateRange = {
  start: Date;
  end: Date;
};

export interface TimeSlot {
  start: string; // HH:mm format
  end: string;   // HH:mm format
  available: boolean;
}

// Configuration types
export interface AppConfig {
  apiUrl: string;
  appName: string;
  version: string;
  environment: 'development' | 'staging' | 'production';
  features: {
    enableDarkMode: boolean;
    enableNotifications: boolean;
    enableAnalytics: boolean;
  };
}

// Generic utility types
export type Nullable<T> = T | null;
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>;
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

// Component ref types
export type ComponentRef<T> = React.RefObject<T> | React.MutableRefObject<T>;
export type ElementRef<T extends keyof JSX.IntrinsicElements> = React.ComponentRef<T>;