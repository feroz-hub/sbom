export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { validateProductionAuth } = await import('./lib/auth/production-config');
    validateProductionAuth();
  }
}
