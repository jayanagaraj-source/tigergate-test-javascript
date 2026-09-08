import { login } from '../src/app.js';

if (!login('admin', 'password123') || login('admin', 'wrong-password')) throw new Error('login failed');
