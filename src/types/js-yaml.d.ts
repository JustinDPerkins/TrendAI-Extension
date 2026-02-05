declare module 'js-yaml' {
    export interface LoadOptions {
        filename?: string;
        onWarning?: (warning: Error) => void;
        schema?: object;
        json?: boolean;
    }

    export interface DumpOptions {
        indent?: number;
        noArrayIndent?: boolean;
        skipInvalid?: boolean;
        flowLevel?: number;
        styles?: Record<string, string>;
        schema?: object;
        sortKeys?: boolean | ((a: string, b: string) => number);
        lineWidth?: number;
        noRefs?: boolean;
        noCompatMode?: boolean;
        condenseFlow?: boolean;
        quotingType?: "'" | '"';
        forceQuotes?: boolean;
        replacer?: (key: string, value: unknown) => unknown;
    }

    export function load(str: string, opts?: LoadOptions): unknown;
    export function loadAll(str: string, iterator?: (doc: unknown) => void, opts?: LoadOptions): unknown[];
    export function dump(obj: unknown, opts?: DumpOptions): string;

    export const JSON_SCHEMA: object;
    export const CORE_SCHEMA: object;
    export const DEFAULT_SCHEMA: object;
    export const FAILSAFE_SCHEMA: object;
}
