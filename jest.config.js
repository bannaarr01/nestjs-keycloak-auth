/** @type {import('jest').Config} */
module.exports = {
   testEnvironment: 'node',
   roots: ['<rootDir>/test'],
   clearMocks: true,
   transform: {
      '^.+\\.ts$': [
         'ts-jest',
         {
            tsconfig: 'tsconfig.spec.json',
         },
      ],
   },
   collectCoverage: true,
   collectCoverageFrom: [
      'src/**/*.ts',
      '!src/interface/**/*.ts',
      '!src/types/**/*.ts',
   ],
   coverageThreshold: {
      global: {
         branches: 100,
         functions: 100,
         lines: 100,
         statements: 100,
      },
   },
};
