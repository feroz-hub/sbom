export type SbomDetectedFormat =
  | 'cyclonedx_json'
  | 'cyclonedx_xml'
  | 'spdx_json'
  | 'spdx_tag_value'
  | 'cyclonedx'
  | 'spdx'
  | 'unknown'
  | string;

export interface SbomFormatDetection {
  detected_format: SbomDetectedFormat;
  detected_spec_version: string | null;
  detection_confidence: number;
  detection_evidence: string[];
}

export function formatSbomFormatLabel(format?: string | null) {
  const normalized = String(format || '').toLowerCase().replace(/[-\s]/g, '_');
  switch (normalized) {
    case 'cyclonedx_json':
      return 'CycloneDX JSON';
    case 'cyclonedx_xml':
      return 'CycloneDX XML';
    case 'cyclonedx':
      return 'CycloneDX';
    case 'spdx_json':
      return 'SPDX JSON';
    case 'spdx_tag_value':
    case 'spdx_tagvalue':
      return 'SPDX Tag-Value';
    case 'spdx':
      return 'SPDX';
    case 'unknown':
    case '':
      return 'Unknown';
    default:
      return format || 'Unknown';
  }
}

export function detectSbomFormatFromText(content: string): SbomFormatDetection {
  const text = (content || '').replace(/^\uFEFF/, '').trimStart();
  if (!text) {
    return {
      detected_format: 'unknown',
      detected_spec_version: null,
      detection_confidence: 0,
      detection_evidence: [],
    };
  }

  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const doc = parsed as Record<string, unknown>;
      if (typeof doc.spdxVersion === 'string') {
        return {
          detected_format: 'spdx_json',
          detected_spec_version: doc.spdxVersion,
          detection_confidence: 0.99,
          detection_evidence: ['spdxVersion'],
        };
      }
      if (String(doc.bomFormat || '').toLowerCase() === 'cyclonedx') {
        return {
          detected_format: 'cyclonedx_json',
          detected_spec_version: typeof doc.specVersion === 'string' ? doc.specVersion : null,
          detection_confidence: 0.99,
          detection_evidence: ['bomFormat'],
        };
      }
    }
    return {
      detected_format: 'unknown',
      detected_spec_version: null,
      detection_confidence: 0,
      detection_evidence: ['json'],
    };
  } catch {
    const head = text.slice(0, 65536);
    const spdxJson = head.match(/"spdxVersion"\s*:\s*"([^"]+)"/i);
    if (spdxJson) {
      return {
        detected_format: 'spdx_json',
        detected_spec_version: spdxJson[1],
        detection_confidence: 0.82,
        detection_evidence: ['spdxVersion'],
      };
    }
    const cyclonedxJson = head.match(/"bomFormat"\s*:\s*"CycloneDX"/i);
    if (cyclonedxJson) {
      const version = head.match(/"specVersion"\s*:\s*"([^"]+)"/i);
      return {
        detected_format: 'cyclonedx_json',
        detected_spec_version: version?.[1] ?? null,
        detection_confidence: 0.82,
        detection_evidence: ['bomFormat'],
      };
    }
  }

  const spdxTagValue = text.match(/^SPDXVersion:\s*(SPDX-[^\s]+)/im);
  if (spdxTagValue) {
    return {
      detected_format: 'spdx_tag_value',
      detected_spec_version: spdxTagValue[1],
      detection_confidence: 0.95,
      detection_evidence: ['SPDXVersion line'],
    };
  }

  if (text.startsWith('<') && /<[^>]*bom\b/i.test(text.slice(0, 65536)) && /cyclonedx/i.test(text.slice(0, 65536))) {
    const version = text.slice(0, 65536).match(/\bversion=["']([^"']+)["']/i);
    return {
      detected_format: 'cyclonedx_xml',
      detected_spec_version: version?.[1] ?? null,
      detection_confidence: 0.9,
      detection_evidence: ['CycloneDX XML bom root'],
    };
  }

  return {
    detected_format: 'unknown',
    detected_spec_version: null,
    detection_confidence: 0,
    detection_evidence: [],
  };
}

export function formatFamily(format?: string | null) {
  const normalized = String(format || '').toLowerCase();
  if (normalized.startsWith('spdx')) return 'spdx';
  if (normalized.startsWith('cyclonedx')) return 'cyclonedx';
  return null;
}
