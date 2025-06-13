# Testing Guide

This project uses Vitest for unit testing and Playwright for end-to-end testing.

## Vitest Setup

### Configuration Files

1. **`vitest.config.ts`** - Main configuration for unit tests

   - Environment: Node
   - Coverage enabled with v8 provider
   - Path aliases configured
   - HTML reporter for test results

2. **`vitest.config.browser.ts`** - Configuration for React component tests
   - Environment: jsdom
   - Includes component test patterns
   - CSS module handling

### Running Tests

```bash
# Run all unit tests
pnpm test

# Run tests in watch mode
pnpm test:unit:watch

# Run tests with coverage
pnpm test:coverage

# Open Vitest UI
pnpm test:unit:ui

# Run e2e tests
pnpm test:e2e
```

### Test Structure

```
tests/
├── unit/
│   ├── setup.ts          # Global test setup
│   ├── setup.browser.ts  # Browser/React test setup (create when needed)
│   └── lib/
│       └── utils.test.ts # Example unit test
└── e2e/
    └── chat.spec.ts      # Playwright e2e tests
```

### Writing Tests

#### Unit Tests

Place unit tests next to the source files or in the `tests/unit` directory:

```typescript
import { describe, it, expect } from 'vitest';

describe('MyFunction', () => {
  it('should work correctly', () => {
    expect(myFunction()).toBe(expectedResult);
  });
});
```

#### Component Tests

For React components, install additional dependencies:

```bash
pnpm add -D @testing-library/react @testing-library/jest-dom @testing-library/user-event jsdom
```

Then create tests like:

```typescript
import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import MyComponent from './MyComponent'

describe('MyComponent', () => {
  it('renders correctly', () => {
    render(<MyComponent />)
    expect(screen.getByText('Hello')).toBeInTheDocument()
  })
})
```

### Coverage

Coverage reports are generated in the `/coverage` directory. The configuration
enforces:

- 80% threshold for lines, functions, branches, and statements
- HTML, JSON, and LCOV reporters
- Excludes test files, type definitions, and config files

### Mocking

The setup includes mocks for:

- Next.js navigation (`useRouter`, `usePathname`, `useSearchParams`)
- `ResizeObserver`
- `window.matchMedia`

### Path Aliases

The following path aliases are configured:

- `@/` - Project root
- `@/app` - App directory
- `@/components` - Components directory
- `@/lib` - Library/utilities directory
- `@/hooks` - Custom hooks directory
- `@/types` - Type definitions directory
