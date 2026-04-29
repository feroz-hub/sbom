/**
 * Pluralization helper — uses ``Intl.PluralRules`` so future i18n is a
 * drop-in. Don't hardcode "(s)" or English fallbacks at call sites.
 *
 * Usage:
 *   pluralize(1, 'SBOM', 'SBOMs')       → '1 SBOM'
 *   pluralize(0, 'project', 'projects') → '0 projects'
 *   pluralize(2, 'finding', 'findings') → '2 findings'
 */
export function pluralize(
  n: number,
  singular: string,
  plural: string,
  locale = 'en',
): string {
  const formatted = new Intl.NumberFormat(locale).format(n);
  // Intl.PluralRules can return 'one' / 'other' (English) or richer
  // categories in other locales. We map anything not 'one' to plural so the
  // caller never has to think about other categories until we add real
  // localisation.
  const rule = new Intl.PluralRules(locale).select(n);
  const word = rule === 'one' ? singular : plural;
  return `${formatted} ${word}`;
}
