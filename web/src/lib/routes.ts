export type AppRoute = 'login' | 'console' | 'proxy-pool' | 'mail' | 'outlook-mail' | 'accounts' | 'registration' | 'upload-config';

export function routeFromPath(pathname: string): AppRoute {
  const normalized = pathname.replace(/\/+$/, '') || '/';
  if (normalized === '/login') return 'login';
  if (normalized === '/' || normalized === '/console') return 'console';
  if (normalized === '/proxy-pool') return 'proxy-pool';
  if (normalized === '/mail') return 'mail';
  if (normalized === '/outlook-mail') return 'outlook-mail';
  if (normalized === '/accounts') return 'accounts';
  if (normalized === '/registration') return 'registration';
  if (normalized === '/upload-config') return 'upload-config';
  return 'console';
}

export function pathForRoute(route: AppRoute): string {
  if (route === 'login') return '/login';
  if (route === 'console') return '/console';
  if (route === 'proxy-pool') return '/proxy-pool';
  if (route === 'mail') return '/mail';
  if (route === 'outlook-mail') return '/outlook-mail';
  if (route === 'accounts') return '/accounts';
  if (route === 'registration') return '/registration';
  if (route === 'upload-config') return '/upload-config';
  return '/console';
}
