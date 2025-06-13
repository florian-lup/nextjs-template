import { describe, it, expect } from 'vitest';

import { cn } from '@/lib/utils';

describe('Example Tests', () => {
  it('should add two numbers', () => {
    const add = (a: number, b: number) => a + b;
    expect(add(2, 3)).toBe(5);
  });

  it('should combine class names with cn utility', () => {
    expect(cn('btn', 'btn-primary')).toBe('btn btn-primary');
  });
});
