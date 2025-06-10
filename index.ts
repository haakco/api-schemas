/**
 * @haakco/api-schemas
 * 
 * Comprehensive Zod schema collections for API validation, type generation, and data validation.
 * Extracted from CourierBoost platform with extensive schema patterns and validation utilities.
 */

// ============================================
// Core Schema Collections
// ============================================

// Common schemas and utilities
export {
  // Base schemas
  uuidSchema,
  emailSchema,
  urlSchema,
  datetimeSchema,
  phoneSchema,
  slugSchema,
  passwordSchema,
  usernameSchema,
  hexColorSchema,
  isoDateSchema,
  isoTimeSchema,
  versionSchema,
  
  // Entity schemas
  entityBaseSchema,
  namedEntitySchema,
  typeBaseSchema,
  typeMapSchema,
  moneySchema,
  locationSchema,
  addressSchema,
  phoneNumberSchema,
  documentSchema,
  
  // Response wrappers
  dataResponseSchema,
  mapResponseSchema,
  paginatedResponseSchema,
  successResponseSchema,
  errorResponseSchema,
  
  // Utility functions
  nullable,
  optional,
  emptyStringAsNull,
  trimmedString,
  nonEmptyString,
  arrayWithConstraints,
} from './common';

// Authentication schemas
export {
  // Request schemas
  loginRequestSchema,
  registerRequestSchema,
  passwordResetRequestSchema,
  passwordResetConfirmSchema,
  changePasswordSchema,
  userProfileUpdateSchema,
  userPreferencesSchema,
  apiKeyCreateSchema,
  twoFactorSetupSchema,
  twoFactorVerifySchema,
  oauthCallbackSchema,
  
  // Data schemas
  jwtTokenSchema,
  apiKeySchema,
  sessionSchema,
  permissionSchema,
  roleSchema,
  authUserSchema,
  
  // Response schemas
  loginResponseSchema,
  registerResponseSchema,
  tokenRefreshResponseSchema,
  passwordResetResponseSchema,
  emailVerificationResponseSchema,
  
  // OAuth
  oauthProviderSchema,
  
  // Types
  type LoginRequest,
  type RegisterRequest,
  type PasswordResetRequest,
  type PasswordResetConfirm,
  type ChangePassword,
  type JwtToken,
  type UserProfileUpdate,
  type UserPreferences,
  type ApiKeyCreate,
  type ApiKey,
  type Session,
  type TwoFactorSetup,
  type TwoFactorVerify,
  type OauthCallback,
  type Permission,
  type Role,
  type AuthUser,
  type LoginResponse,
  type RegisterResponse,
  type TokenRefreshResponse,
  type PasswordResetResponse,
  type EmailVerificationResponse,
} from './auth';

// Validation schemas and utilities
export {
  // Field validation
  usernameValidationSchema,
  emailValidationSchema,
  phoneValidationSchema,
  passwordStrengthSchema,
  
  // Form validation
  contactFormSchema,
  fileUploadSchema,
  documentUploadSchema,
  addressValidationSchema,
  creditCardSchema,
  searchFilterSchema,
  
  // Bulk operations
  bulkUpdateSchema,
  bulkImportSchema,
  
  // Dynamic validation builders
  createDynamicFormSchema,
  createConditionalSchema,
  
  // Validation utilities
  createDebouncedValidator,
  transformValidationErrors,
  getValidationSummary,
  
  // Types
  type ContactForm,
  type FileUpload,
  type DocumentUpload,
  type AddressValidation,
  type CreditCard,
  type SearchFilter,
  type BulkUpdate,
  type BulkImport,
  type ValidationErrors,
  type ValidationSummary,
} from './validation';

// ============================================
// Schema Collections by Domain
// ============================================

/**
 * Common schemas for basic data types and API responses
 */
export const commonSchemas = {
  uuid: uuidSchema,
  email: emailSchema,
  url: urlSchema,
  datetime: datetimeSchema,
  phone: phoneSchema,
  slug: slugSchema,
  password: passwordSchema,
  username: usernameSchema,
  hexColor: hexColorSchema,
  isoDate: isoDateSchema,
  isoTime: isoTimeSchema,
  version: versionSchema,
  entity: entityBaseSchema,
  namedEntity: namedEntitySchema,
  typeBase: typeBaseSchema,
  typeMap: typeMapSchema,
  money: moneySchema,
  location: locationSchema,
  address: addressSchema,
  phoneNumber: phoneNumberSchema,
  document: documentSchema,
};

/**
 * Response wrapper schemas for API endpoints
 */
export const responseSchemas = {
  data: dataResponseSchema,
  map: mapResponseSchema,
  paginated: paginatedResponseSchema,
  success: successResponseSchema,
  error: errorResponseSchema,
};

/**
 * Authentication and authorization schemas
 */
export const authSchemas = {
  loginRequest: loginRequestSchema,
  registerRequest: registerRequestSchema,
  passwordResetRequest: passwordResetRequestSchema,
  passwordResetConfirm: passwordResetConfirmSchema,
  changePassword: changePasswordSchema,
  userProfileUpdate: userProfileUpdateSchema,
  userPreferences: userPreferencesSchema,
  apiKeyCreate: apiKeyCreateSchema,
  jwtToken: jwtTokenSchema,
  apiKey: apiKeySchema,
  session: sessionSchema,
  twoFactorSetup: twoFactorSetupSchema,
  twoFactorVerify: twoFactorVerifySchema,
  oauthCallback: oauthCallbackSchema,
  permission: permissionSchema,
  role: roleSchema,
  authUser: authUserSchema,
  loginResponse: loginResponseSchema,
  registerResponse: registerResponseSchema,
  tokenRefreshResponse: tokenRefreshResponseSchema,
  passwordResetResponse: passwordResetResponseSchema,
  emailVerificationResponse: emailVerificationResponseSchema,
};

/**
 * Form and field validation schemas
 */
export const validationSchemas = {
  usernameValidation: usernameValidationSchema,
  emailValidation: emailValidationSchema,
  phoneValidation: phoneValidationSchema,
  passwordStrength: passwordStrengthSchema,
  contactForm: contactFormSchema,
  fileUpload: fileUploadSchema,
  documentUpload: documentUploadSchema,
  addressValidation: addressValidationSchema,
  creditCard: creditCardSchema,
  searchFilter: searchFilterSchema,
  bulkUpdate: bulkUpdateSchema,
  bulkImport: bulkImportSchema,
};

/**
 * Utility functions for schema manipulation
 */
export const schemaUtils = {
  nullable,
  optional,
  emptyStringAsNull,
  trimmedString,
  nonEmptyString,
  arrayWithConstraints,
  createDynamicFormSchema,
  createConditionalSchema,
  createDebouncedValidator,
  transformValidationErrors,
  getValidationSummary,
};

// ============================================
// Default Export
// ============================================

/**
 * Default export with all schema collections organized by domain
 */
export default {
  common: commonSchemas,
  responses: responseSchemas,
  auth: authSchemas,
  validation: validationSchemas,
  utils: schemaUtils,
};

// Re-export zod for convenience
export { z } from 'zod';

// ============================================
// Version Information
// ============================================

export const SCHEMA_VERSION = '1.0.0';
export const SUPPORTED_ZOD_VERSION = '^3.22.0';

/**
 * Get schema library information
 */
export const getSchemaInfo = () => ({
  version: SCHEMA_VERSION,
  supportedZodVersion: SUPPORTED_ZOD_VERSION,
  totalSchemas: {
    common: Object.keys(commonSchemas).length,
    responses: Object.keys(responseSchemas).length,
    auth: Object.keys(authSchemas).length,
    validation: Object.keys(validationSchemas).length,
    utils: Object.keys(schemaUtils).length,
  },
  description: 'Comprehensive Zod schema collections extracted from CourierBoost platform',
});

/**
 * Usage example:
 * 
 * ```typescript
 * import { 
 *   commonSchemas, 
 *   authSchemas, 
 *   validationSchemas,
 *   schemaUtils 
 * } from '@haakco/api-schemas';
 * 
 * // Use common schemas
 * const userSchema = z.object({
 *   id: commonSchemas.uuid,
 *   email: commonSchemas.email,
 *   name: commonSchemas.nonEmptyString,
 * });
 * 
 * // Use auth schemas
 * const loginData = authSchemas.loginRequest.parse({
 *   email: 'user@example.com',
 *   password: 'securepass123',
 * });
 * 
 * // Use validation utilities
 * const errors = schemaUtils.transformValidationErrors(zodError);
 * const summary = schemaUtils.getValidationSummary(errors);
 * ```
 */