declare module 'archiver' {
    import { Readable, Transform } from 'stream';

    interface ArchiverOptions {
        zlib?: {
            level?: number;
        };
        store?: boolean;
    }

    interface EntryData {
        name?: string;
        prefix?: string;
        date?: Date | string;
        mode?: number;
        stats?: object;
    }

    interface GlobOptions {
        cwd?: string;
        ignore?: string | string[];
        dot?: boolean;
        expand?: boolean;
    }

    interface Archiver extends Transform {
        abort(): this;
        append(source: Readable | Buffer | string, data?: EntryData): this;
        directory(dirpath: string, destpath: string | false, data?: EntryData): this;
        file(filename: string, data?: EntryData): this;
        glob(pattern: string, options?: GlobOptions, data?: EntryData): this;
        finalize(): Promise<void>;
        setFormat(format: string): this;
        setModule(module: Function): this;
        pointer(): number;

        on(event: 'data', listener: (chunk: Buffer) => void): this;
        on(event: 'end', listener: () => void): this;
        on(event: 'error', listener: (err: Error) => void): this;
        on(event: 'warning', listener: (err: Error) => void): this;
        on(event: 'progress', listener: (progress: { entries: { total: number; processed: number }; fs: { totalBytes: number; processedBytes: number } }) => void): this;
    }

    function archiver(format: 'zip' | 'tar' | 'json', options?: ArchiverOptions): Archiver;

    export = archiver;
}
