import {defineConfig} from '@playwright/test';
import config from './playwright.config.ts';

export default defineConfig({...config, testMatch: /enterprise-authz\.authz\.ts$/});
