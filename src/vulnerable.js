// Intentional security-test fixture.
export const unsafeQuery = input => `SELECT * FROM users WHERE name = '${input}'`;
