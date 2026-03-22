export interface ExampleUser {
  sub?: string;
  sid?: string;
  scope?: string;
  preferred_username?: string;
  realm_access?: { roles?: string[] };
  resource_access?: Record<string, { roles?: string[] }>;
  [key: string]: unknown;
}
