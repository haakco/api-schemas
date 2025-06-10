import { z } from 'zod';
import { emailSchema, passwordSchema, usernameSchema, uuidSchema, phoneSchema } from './common';

// ============================================
// Authentication Schemas
// ============================================

/**
 * Login request schema
 */
export const loginRequestSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Password is required'),
  remember?: z.boolean().optional(),
  deviceName?: z.string().optional(),
});

/**
 * Registration request schema
 */
export const registerRequestSchema = z.object({
  firstname: z.string().min(1, 'First name is required'),
  lastname: z.string().min(1, 'Last name is required'),
  email: emailSchema,
  password: passwordSchema,
  passwordConfirmation: z.string(),
  username: usernameSchema.optional(),
  phoneNumber: phoneSchema.optional(),
  acceptTerms: z.boolean().refine(val => val === true, 'You must accept the terms'),
}).refine(data => data.password === data.passwordConfirmation, {
  message: 'Passwords do not match',
  path: ['passwordConfirmation'],
});

/**
 * Password reset request schema
 */
export const passwordResetRequestSchema = z.object({
  email: emailSchema,
});

/**
 * Password reset confirmation schema
 */
export const passwordResetConfirmSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  email: emailSchema,
  password: passwordSchema,
  passwordConfirmation: z.string(),
}).refine(data => data.password === data.passwordConfirmation, {
  message: 'Passwords do not match',
  path: ['passwordConfirmation'],
});

/**
 * Change password schema
 */
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: passwordSchema,
  newPasswordConfirmation: z.string(),
}).refine(data => data.newPassword === data.newPasswordConfirmation, {
  message: 'New passwords do not match',
  path: ['newPasswordConfirmation'],
});

/**
 * JWT token schema
 */
export const jwtTokenSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string().optional(),
  tokenType: z.string().default('Bearer'),
  expiresIn: z.number().optional(),
  scope: z.string().optional(),
  issuedAt: z.string().datetime().optional(),
});

/**
 * User profile update schema
 */
export const userProfileUpdateSchema = z.object({
  firstname: z.string().min(1, 'First name is required').optional(),
  lastname: z.string().min(1, 'Last name is required').optional(),
  email: emailSchema.optional(),
  username: usernameSchema.optional(),
  phoneNumber: phoneSchema.optional(),
  bio: z.string().max(500, 'Bio must not exceed 500 characters').optional(),
  website: z.string().url('Must be a valid URL').optional(),
  timezone: z.string().optional(),
  locale: z.string().optional(),
});

/**
 * User preferences schema
 */
export const userPreferencesSchema = z.object({
  theme: z.enum(['light', 'dark', 'system']).default('system'),
  language: z.string().default('en'),
  notifications: z.object({
    email: z.boolean().default(true),
    push: z.boolean().default(true),
    sms: z.boolean().default(false),
    marketing: z.boolean().default(false),
  }).default({}),
  privacy: z.object({
    profileVisibility: z.enum(['public', 'private', 'friends']).default('public'),
    showEmail: z.boolean().default(false),
    showPhone: z.boolean().default(false),
  }).default({}),
});

/**
 * API key creation schema
 */
export const apiKeyCreateSchema = z.object({
  name: z.string().min(1, 'API key name is required'),
  description: z.string().optional(),
  expiresAt: z.string().datetime().optional(),
  permissions: z.array(z.string()).default([]),
  ipWhitelist: z.array(z.string().ip()).optional(),
});

/**
 * API key schema
 */
export const apiKeySchema = z.object({
  uuid: uuidSchema,
  name: z.string(),
  description: z.string().optional(),
  keyPreview: z.string(), // First few and last few characters
  permissions: z.array(z.string()),
  ipWhitelist: z.array(z.string().ip()).optional(),
  lastUsedAt: z.string().datetime().nullable(),
  expiresAt: z.string().datetime().nullable(),
  isActive: z.boolean(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

/**
 * Session information schema
 */
export const sessionSchema = z.object({
  uuid: uuidSchema,
  userAgent: z.string().optional(),
  ipAddress: z.string().ip().optional(),
  lastActivity: z.string().datetime(),
  expiresAt: z.string().datetime().optional(),
  isCurrent: z.boolean(),
  deviceType: z.enum(['desktop', 'mobile', 'tablet', 'unknown']).optional(),
  location: z.object({
    country: z.string().optional(),
    city: z.string().optional(),
    region: z.string().optional(),
  }).optional(),
  createdAt: z.string().datetime(),
});

/**
 * Two-factor authentication setup schema
 */
export const twoFactorSetupSchema = z.object({
  qrCodeUrl: z.string().url(),
  secret: z.string(),
  backupCodes: z.array(z.string()),
});

/**
 * Two-factor authentication verification schema
 */
export const twoFactorVerifySchema = z.object({
  code: z.string().length(6, 'Verification code must be 6 digits'),
  type: z.enum(['totp', 'backup']).default('totp'),
});

/**
 * OAuth provider schemas
 */
export const oauthProviderSchema = z.enum(['google', 'github', 'facebook', 'twitter', 'linkedin']);

export const oauthCallbackSchema = z.object({
  provider: oauthProviderSchema,
  code: z.string(),
  state: z.string().optional(),
  scope: z.string().optional(),
});

/**
 * Permission and role schemas
 */
export const permissionSchema = z.object({
  uuid: uuidSchema,
  name: z.string(),
  slug: z.string(),
  description: z.string().optional(),
  category: z.string().optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

export const roleSchema = z.object({
  uuid: uuidSchema,
  name: z.string(),
  slug: z.string(),
  description: z.string().optional(),
  level: z.number().min(0).max(100),
  permissions: z.array(permissionSchema),
  isSystem: z.boolean().default(false),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

/**
 * User with authentication details
 */
export const authUserSchema = z.object({
  uuid: uuidSchema,
  firstname: z.string(),
  lastname: z.string(),
  email: z.string().email(),
  username: z.string().optional(),
  emailVerifiedAt: z.string().datetime().nullable(),
  phoneNumber: z.string().optional(),
  phoneVerifiedAt: z.string().datetime().nullable(),
  profilePictureUrl: z.string().url().nullable(),
  profilePictureThumbUrl: z.string().url().nullable(),
  twoFactorEnabled: z.boolean().default(false),
  isActive: z.boolean().default(true),
  lastLoginAt: z.string().datetime().nullable(),
  preferences: userPreferencesSchema.optional(),
  roles: z.array(roleSchema).default([]),
  permissions: z.array(permissionSchema).default([]),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

// ============================================
// Authentication Response Schemas
// ============================================

/**
 * Login response schema
 */
export const loginResponseSchema = z.object({
  user: authUserSchema,
  token: jwtTokenSchema.optional(),
  message: z.string().optional(),
  requiresTwoFactor: z.boolean().default(false),
});

/**
 * Registration response schema
 */
export const registerResponseSchema = z.object({
  user: authUserSchema,
  token: jwtTokenSchema.optional(),
  message: z.string(),
  verificationRequired: z.boolean().default(false),
});

/**
 * Token refresh response schema
 */
export const tokenRefreshResponseSchema = z.object({
  token: jwtTokenSchema,
  user: authUserSchema.optional(),
});

/**
 * Password reset response schema
 */
export const passwordResetResponseSchema = z.object({
  message: z.string(),
  resetToken: z.string().optional(), // Only in development
});

/**
 * Email verification response schema
 */
export const emailVerificationResponseSchema = z.object({
  message: z.string(),
  verified: z.boolean(),
  user: authUserSchema.optional(),
});

// Type exports for TypeScript
export type LoginRequest = z.infer<typeof loginRequestSchema>;
export type RegisterRequest = z.infer<typeof registerRequestSchema>;
export type PasswordResetRequest = z.infer<typeof passwordResetRequestSchema>;
export type PasswordResetConfirm = z.infer<typeof passwordResetConfirmSchema>;
export type ChangePassword = z.infer<typeof changePasswordSchema>;
export type JwtToken = z.infer<typeof jwtTokenSchema>;
export type UserProfileUpdate = z.infer<typeof userProfileUpdateSchema>;
export type UserPreferences = z.infer<typeof userPreferencesSchema>;
export type ApiKeyCreate = z.infer<typeof apiKeyCreateSchema>;
export type ApiKey = z.infer<typeof apiKeySchema>;
export type Session = z.infer<typeof sessionSchema>;
export type TwoFactorSetup = z.infer<typeof twoFactorSetupSchema>;
export type TwoFactorVerify = z.infer<typeof twoFactorVerifySchema>;
export type OauthCallback = z.infer<typeof oauthCallbackSchema>;
export type Permission = z.infer<typeof permissionSchema>;
export type Role = z.infer<typeof roleSchema>;
export type AuthUser = z.infer<typeof authUserSchema>;
export type LoginResponse = z.infer<typeof loginResponseSchema>;
export type RegisterResponse = z.infer<typeof registerResponseSchema>;
export type TokenRefreshResponse = z.infer<typeof tokenRefreshResponseSchema>;
export type PasswordResetResponse = z.infer<typeof passwordResetResponseSchema>;
export type EmailVerificationResponse = z.infer<typeof emailVerificationResponseSchema>;