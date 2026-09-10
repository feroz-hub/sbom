export const PRODUCT_CATEGORY_MAX_LENGTH = 128;

export const PRODUCT_CATEGORIES = [
  { code: 'MEDICAL_DEVICE_SOFTWARE', label: 'Medical Device Software' },
  { code: 'MEDICAL_DEVICE_GATEWAY', label: 'Medical Device Gateway' },
  { code: 'EMBEDDED_FIRMWARE', label: 'Embedded / Firmware' },
  { code: 'IOT_EDGE_DEVICE', label: 'IoT / Edge Device' },
  { code: 'ENTERPRISE_WEB_APP', label: 'Enterprise Web Application' },
  { code: 'API_BACKEND_SERVICE', label: 'API / Backend Service' },
  { code: 'MICROSERVICE_CONTAINER', label: 'Microservice / Container Application' },
  { code: 'CLOUD_SAAS', label: 'Cloud / SaaS Application' },
  { code: 'DESKTOP_APP', label: 'Desktop Application' },
  { code: 'MOBILE_APP', label: 'Mobile Application' },
  { code: 'LIBRARY_SDK_FRAMEWORK', label: 'Library / SDK / Framework' },
  { code: 'DATABASE_DATA_PLATFORM', label: 'Database / Data Platform' },
  { code: 'OS_PLATFORM', label: 'Operating System / Platform' },
  { code: 'DEVOPS_INFRASTRUCTURE', label: 'DevOps / Infrastructure Tool' },
  { code: 'SECURITY_PLATFORM', label: 'Security / Cybersecurity Platform' },
  { code: 'AI_ML_APPLICATION', label: 'AI / ML Application' },
  { code: 'OTHER', label: 'Other' },
] as const;

export type ProductCategoryCode = (typeof PRODUCT_CATEGORIES)[number]['code'];
export type ProductCategorySelection = ProductCategoryCode | '';

export const CUSTOM_PRODUCT_CATEGORY_CODE: ProductCategoryCode = 'OTHER';

export function getProductCategoryOption(value: string | null | undefined) {
  const normalizedValue = value?.trim();
  if (!normalizedValue) return undefined;
  return PRODUCT_CATEGORIES.find((category) => category.label === normalizedValue);
}

export function isStandardProductCategory(value: string | null | undefined): boolean {
  return getProductCategoryOption(value) !== undefined;
}

export function getProductCategoryFormValue(value: string | null | undefined): {
  selectedCategory: ProductCategorySelection;
  customCategory: string;
} {
  const normalizedValue = value?.trim() ?? '';
  if (!normalizedValue) return { selectedCategory: '', customCategory: '' };

  const option = getProductCategoryOption(normalizedValue);
  if (option && option.code !== CUSTOM_PRODUCT_CATEGORY_CODE) {
    return { selectedCategory: option.code, customCategory: '' };
  }

  return {
    selectedCategory: CUSTOM_PRODUCT_CATEGORY_CODE,
    customCategory: normalizedValue,
  };
}

export function resolveProductCategory(
  selectedCategory: ProductCategorySelection,
  customCategory: string,
): string | null {
  if (!selectedCategory) return null;
  if (selectedCategory === CUSTOM_PRODUCT_CATEGORY_CODE) return customCategory.trim() || null;
  return PRODUCT_CATEGORIES.find((category) => category.code === selectedCategory)?.label ?? null;
}
