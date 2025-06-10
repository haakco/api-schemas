import { z } from 'zod';

// ============================================
// Common Base Schemas
// ============================================

export const uuidSchema = z.string().uuid();
export const emailSchema = z.string().email();
export const urlSchema = z.string().url();
export const datetimeSchema = z.string().datetime();
export const phoneSchema = z.string().regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format');
export const slugSchema = z.string().regex(/^[a-z0-9-]+$/, 'Must contain only lowercase letters, numbers, and hyphens');

// Common entity base schema
export const entityBaseSchema = z.object({
  uuid: uuidSchema,
  createdAt: datetimeSchema,
  updatedAt: datetimeSchema,
});

// Extended entity with common fields
export const namedEntitySchema = entityBaseSchema.extend({
  name: z.string().min(1, 'Name is required'),
  description: z.string().optional(),
  isActive: z.boolean().default(true),
});

// Type schemas for standardized type objects
export const typeBaseSchema = z.object({
  uuid: uuidSchema,
  slug: slugSchema,
  name: z.string(),
  description: z.string().optional(),
  isActive: z.boolean().optional(),
  createdAt: datetimeSchema.optional(),
  updatedAt: datetimeSchema.optional(),
});

export const typeMapSchema = z.record(z.string(), typeBaseSchema);

// Money/currency schema
export const moneySchema = z.object({
  amount: z.number(),
  currency: z.string().length(3, 'Currency must be 3 characters (ISO 4217)'),
  cents: z.number().optional(),
});

// Location schema
export const locationSchema = z.object({
  lat: z.number().min(-90).max(90),
  lng: z.number().min(-180).max(180),
  accuracy: z.number().optional(),
  altitude: z.number().optional(),
});

// Address schema
export const addressSchema = z.object({
  uuid: uuidSchema,
  line1: z.string().min(1, 'Address line 1 is required'),
  line2: z.string().optional(),
  line3: z.string().optional(),
  city: z.string().min(1, 'City is required'),
  county: z.string().optional(),
  postcode: z.string().min(1, 'Postcode is required'),
  countryCode: z.string().length(2, 'Country code must be 2 characters'),
  location: locationSchema.optional(),
});

// Phone number schema
export const phoneNumberSchema = z.object({
  uuid: uuidSchema,
  phoneNumber: phoneSchema,
  phoneNumberType: z.string().optional(),
  isPrimary: z.boolean().default(false),
});

// File/document schema
export const documentSchema = z.object({
  uuid: uuidSchema,
  originalName: z.string(),
  mimeType: z.string(),
  extension: z.string(),
  sizeBytes: z.number().positive(),
  url: urlSchema.optional(),
  isChecked: z.boolean().default(false),
  isValid: z.boolean().default(true),
  documentTypeSlug: z.string().optional(),
  createdAt: datetimeSchema,
  updatedAt: datetimeSchema,
});

// ============================================
// API Response Wrappers
// ============================================

/**
 * Generic data wrapper for API responses
 */
export const dataResponseSchema = <T extends z.ZodTypeAny>(dataSchema: T) =>
  z.object({
    data: dataSchema,
  });

/**
 * Generic map response for key-value API responses
 */
export const mapResponseSchema = <T extends z.ZodTypeAny>(itemSchema: T) =>
  z.object({
    data: z.record(z.string(), itemSchema),
  });

/**
 * Generic paginated response for list endpoints
 */
export const paginatedResponseSchema = <T extends z.ZodTypeAny>(itemSchema: T) =>
  z.object({
    data: z.array(itemSchema),
    meta: z.object({
      current_page: z.number(),
      from: z.number().nullable(),
      last_page: z.number(),
      per_page: z.number(),
      to: z.number().nullable(),
      total: z.number(),
    }),
    links: z.object({
      first: z.string().nullable(),
      last: z.string().nullable(),
      prev: z.string().nullable(),
      next: z.string().nullable(),
    }),
  });

/**
 * Standard success response schema
 */
export const successResponseSchema = z.object({
  message: z.string(),
  success: z.boolean().default(true),
});

/**
 * Standard error response schema
 */
export const errorResponseSchema = z.object({
  message: z.string(),
  errors: z.record(z.array(z.string())).optional(),
  code: z.string().optional(),
  statusCode: z.number().optional(),
});

// ============================================
// Common Validation Patterns
// ============================================

/**
 * Password validation schema
 */
export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[!@#$%^&*(),.?\":{}|<>]/, 'Password must contain at least one special character');

/**
 * Username validation schema
 */
export const usernameSchema = z
  .string()
  .min(3, 'Username must be at least 3 characters')
  .max(30, 'Username must not exceed 30 characters')
  .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens');

/**
 * Color hex validation schema
 */
export const hexColorSchema = z
  .string()
  .regex(/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/, 'Must be a valid hex color');

/**
 * ISO date validation schema
 */
export const isoDateSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be in YYYY-MM-DD format')
  .refine((date) => {
    const parsed = new Date(date);
    return !isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === date;
  }, 'Invalid date');

/**
 * ISO time validation schema
 */
export const isoTimeSchema = z
  .string()
  .regex(/^\d{2}:\d{2}(:\d{2})?$/, 'Time must be in HH:MM or HH:MM:SS format');

/**
 * Version number validation schema
 */
export const versionSchema = z
  .string()
  .regex(/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$/, 'Must be a valid semantic version (e.g., 1.0.0 or 1.0.0-beta.1)');

// ============================================
// Utility Functions
// ============================================

/**
 * Create a nullable version of any schema
 */
export const nullable = <T extends z.ZodTypeAny>(schema: T) => schema.nullable();

/**
 * Create an optional version of any schema
 */
export const optional = <T extends z.ZodTypeAny>(schema: T) => schema.optional();

/**
 * Create a schema that accepts empty strings as null
 */
export const emptyStringAsNull = <T extends z.ZodTypeAny>(schema: T) =>
  z.preprocess((val) => (val === '' ? null : val), schema);

/**
 * Trim strings before validation
 */
export const trimmedString = z.string().transform((val) => val.trim());

/**
 * Non-empty trimmed string
 */
export const nonEmptyString = trimmedString.min(1, 'This field cannot be empty');

/**
 * Create an array schema with min/max constraints
 */
export const arrayWithConstraints = <T extends z.ZodTypeAny>(
  itemSchema: T,
  options: {
    min?: number;
    max?: number;
    minMessage?: string;
    maxMessage?: string;
  } = {},
) => {
  const { min = 0, max, minMessage, maxMessage } = options;
  
  let schema = z.array(itemSchema);
  
  if (min > 0) {
    schema = schema.min(min, minMessage || `At least ${min} item(s) required`);
  }
  
  if (max !== undefined) {
    schema = schema.max(max, maxMessage || `At most ${max} item(s) allowed`);
  }
  
  return schema;
};